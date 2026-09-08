#!/usr/bin/env python3
"""Run one legacy watcher pass under a POSIX lock, with durable run records.

Deploy the legacy check.sh into the state directory if it hardcodes its own DIR.
Exit 75 means lock contention; exit 124 means the process group timed out.
"""

import argparse
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def positive_timeout(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return number


def durable_status(state, status):
    # Same-directory replacement keeps readers from seeing partial JSON.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=state, prefix=".status-", delete=False
    ) as output:
        json.dump(status, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
        temporary = output.name
    os.replace(temporary, state / "status.json")
    directory = os.open(state, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(args, state):
    status_path = state / "status.json"
    # Fail closed on unreadable/corrupt status rather than erase success history.
    previous = json.loads(status_path.read_text()) if status_path.exists() else {}
    started = timestamp()
    script = args.script.expanduser() if args.script else state / "check.sh"
    timed_out = False
    interrupted = None
    child = None

    def kill_group():
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def cancel(signum, _frame):
        nonlocal interrupted
        interrupted = interrupted or signum
        kill_group()

    with (state / "watcher.log").open("a", encoding="utf-8") as log:
        def record(message):
            log.write(f"[{timestamp()}] {message}\n")
            log.flush()
            os.fsync(log.fileno())

        record(f"started script={script}")
        handlers = {sig: signal.signal(sig, cancel)
                    for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            child = subprocess.Popen(
                ["bash", str(script)],
                env={**os.environ, "ONCE": "1"},
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            # A signal can arrive while Popen is assigning the child handle.
            if interrupted:
                kill_group()
            try:
                output, _ = child.communicate(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                kill_group()
                output, _ = child.communicate()
            code = 128 + interrupted if interrupted else (124 if timed_out else child.returncode)
            if code < 0:
                code = 128 - code
            text = output.decode("utf-8", errors="replace")
        except OSError as error:
            code = 127
            text = f"unable to start watcher: {error}\n"
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
        if interrupted:
            code = 128 + interrupted
            text += f"watcher interrupted by signal {interrupted}\n"
        for line in text.splitlines():
            record(line)
        finished = timestamp()
        record(f"finished_at={finished} returncode={code} timed_out={timed_out}")
        durable_status(state, {
            "started_at": started,
            "finished_at": finished,
            "returncode": code,
            "timed_out": timed_out,
            "last_success_at": finished if code == 0 else previous.get("last_success_at"),
        })
        # Record outcome even when the caller has closed its output pipe.
        try:
            print(text, end="", flush=True)
        except BrokenPipeError:
            pass
        return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("~/.local/state/amule-pr-watcher"))
    parser.add_argument("--script", type=Path)
    parser.add_argument("--timeout", type=positive_timeout, default=600)
    args = parser.parse_args()
    state = args.state_dir.expanduser()
    try:
        state.mkdir(parents=True, exist_ok=True)
        with (state / "watcher.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("watcher already running", file=sys.stderr)
                return 75
            return run(args, state)
    except (OSError, ValueError) as error:
        print(f"watcher: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
