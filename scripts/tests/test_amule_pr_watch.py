import fcntl
import json
import os
import signal
import shlex
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


WRAPPER = Path(__file__).resolve().parents[1] / "amule-pr-watch.py"
FIXTURES = Path(__file__).resolve().parent / ".amule-pr-watch-fixtures"


class WatchTests(unittest.TestCase):
    def setUp(self):
        FIXTURES.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=FIXTURES)
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        self.script = self.state / "check.sh"

    def run_watch(self, body, *args):
        self.script.write_text(body)
        return subprocess.run(
            [sys.executable, str(WRAPPER), "--state-dir", str(self.state), *args],
            capture_output=True, text=True, timeout=10,
        )

    def status(self):
        return json.loads((self.state / "status.json").read_text())

    def test_success(self):
        result = self.run_watch('echo "once=$ONCE"; echo warning >&2')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("once=1", result.stdout)
        self.assertIn("warning", result.stdout)
        status = self.status()
        self.assertEqual(status["returncode"], 0)
        self.assertEqual(status["finished_at"], status["last_success_at"])
        log = (self.state / "watcher.log").read_text()
        self.assertIn("once=1", log)
        self.assertIn(status["finished_at"], log)

    def test_failure_preserves_state(self):
        self.assertEqual(self.run_watch("true").returncode, 0)
        success = self.status()["last_success_at"]
        watermark = self.state / "watermark"
        watermark.write_bytes(b"untouched\n")
        result = self.run_watch("echo failed; exit 7")
        self.assertEqual(result.returncode, 7)
        self.assertIn("failed", result.stdout)
        self.assertEqual(self.status()["returncode"], 7)
        self.assertEqual(self.status()["last_success_at"], success)
        self.assertEqual(watermark.read_bytes(), b"untouched\n")

    def test_timeout_kills_group(self):
        marker = self.state / "leaked"
        result = self.run_watch(
            f'echo started; (sleep 1; echo leaked > {shlex.quote(str(marker))}) & wait',
            "--timeout", "0.1",
        )
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("started", result.stdout)
        self.assertTrue(self.status()["timed_out"])
        self.assertIsNone(self.status()["last_success_at"])
        time.sleep(1.2)
        self.assertFalse(marker.exists())

    def test_lock_contention_preserves_status(self):
        self.run_watch("true")
        before = (self.state / "status.json").read_bytes()
        with (self.state / "watcher.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_watch("exit 9")
        self.assertEqual(result.returncode, 75)
        self.assertEqual((self.state / "status.json").read_bytes(), before)

    def test_signals_kill_and_reap_group(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig):
                self.run_watch("true")
                success = self.status()["last_success_at"]
                ready = self.state / f"ready-{sig}"
                leaked = self.state / f"leaked-{sig}"
                self.script.write_text(
                    f'echo $$ > {shlex.quote(str(ready))}; '
                    f'(sleep 0.8; echo leaked > {shlex.quote(str(leaked))}) & wait'
                )
                child = subprocess.Popen(
                    [sys.executable, str(WRAPPER), "--state-dir", str(self.state)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                try:
                    deadline = time.monotonic() + 5
                    while not ready.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(ready.exists())
                    pid = int(ready.read_text())
                    child.send_signal(sig)
                    output, error = child.communicate(timeout=5)
                    self.assertEqual(child.returncode, 128 + sig, error)
                    self.assertIn("interrupted", output)
                    self.assertEqual(self.status()["returncode"], 128 + sig)
                    self.assertEqual(self.status()["last_success_at"], success)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)  # Direct checker child has been reaped.
                    time.sleep(1)
                    self.assertFalse(leaked.exists())
                    self.assertEqual(self.run_watch("true").returncode, 0)
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate()

    def test_explicit_script(self):
        other = self.state / "other.sh"
        other.write_text("echo alternate")
        result = self.run_watch("exit 9", "--script", str(other))
        self.assertEqual(result.returncode, 0)
        self.assertIn("alternate", result.stdout)


if __name__ == "__main__":
    unittest.main()
