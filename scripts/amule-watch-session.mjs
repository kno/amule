// Session-local scheduling only. Other agents can use amule-pr-watch.py directly.
import { spawn as nodeSpawn } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export function createWatcher({
  repoRoot = fileURLToPath(new URL("../", import.meta.url)),
  stateDir = join(homedir(), ".local/state/amule-pr-watcher"),
  spawn = nodeSpawn,
  setInterval = globalThis.setInterval,
  clearInterval = globalThis.clearInterval,
  notify = (_sessionId, _result) => {},
} = {}) {
  let owner, timer, active, stopping, lastResult;
  const status = () => ({
    running: timer !== undefined,
    active: !!active,
    stopping: !!stopping,
    lastResult,
    stateDir,
  });

  function runOnce(sessionId) {
    if (stopping)
      throw new Error("watcher is stopping; wait for child cleanup");
    if (owner && owner.sessionId !== sessionId)
      throw new Error("stop the previous session first");
    owner ??= { sessionId };
    if (active) return active.done;
    const identity = owner;
    let resolve;
    const run = {
      done: new Promise((r) => {
        resolve = r;
      }),
    };
    active = run;
    let text = "",
      error,
      truncated = false;
    const collect = (chunk) => {
      const next = text + chunk.toString();
      truncated ||= next.length > 16000;
      text = next.slice(0, 16000);
    };
    const finish = (code, signal) => {
      if (active !== run) return;
      active = undefined;
      let kind = "error";
      if (!error && code === 75) kind = "contention";
      if (!error && code === 0) kind = text.trim() ? "findings" : "empty";
      const result = { kind, code, text: error?.message ?? text, signal };
      if (truncated)
        result.text += `\n[Truncated; full output in ${stateDir}/watcher.log]`;
      if (owner === identity) {
        lastResult = result;
        if (kind === "findings" || kind === "error") {
          try {
            notify(identity.sessionId, result);
          } catch (failure) {
            lastResult = { ...result, notificationError: String(failure) };
          }
        }
      }
      resolve(result);
    };
    try {
      run.child = spawn(
        "python3",
        [join(repoRoot, "scripts/amule-pr-watch.py"), "--state-dir", stateDir],
        { cwd: repoRoot, detached: false, stdio: ["ignore", "pipe", "pipe"] },
      );
      run.child.stdout.on("data", collect);
      run.child.stderr.on("data", collect);
      // Node emits close after error, too: wait for streams and process reaping.
      run.child.on("error", (failure) => {
        error = failure;
      });
      run.child.once("close", finish);
    } catch (failure) {
      error = failure;
      finish(null, null);
    }
    return run.done;
  }

  function start(sessionId) {
    if (stopping)
      throw new Error("watcher is stopping; wait for child cleanup");
    if (owner && owner.sessionId !== sessionId)
      throw new Error("stop the previous session first");
    if (timer !== undefined) return status();
    owner ??= { sessionId };
    const identity = owner;
    timer = setInterval(() => {
      if (owner === identity && !stopping) void runOnce(sessionId);
    }, 3600000);
    timer.unref?.();
    void runOnce(sessionId);
    return status();
  }

  function stop() {
    if (stopping) return stopping;
    owner = undefined; // Invalidate before any await or late close callback.
    if (timer !== undefined) clearInterval(timer);
    timer = undefined;
    if (!active) return Promise.resolve();
    const run = active;
    // Do not SIGKILL Python: it owns the checker process group's cleanup.
    // Wait for close, not just exit, so the child is reaped and pipes drained.
    stopping = run.done.then(() => {
      stopping = undefined;
    });
    run.child.kill("SIGTERM");
    return stopping;
  }
  return { start, stop, runOnce, status };
}
