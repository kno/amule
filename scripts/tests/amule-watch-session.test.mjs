import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFile, mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { runInNewContext } from 'node:vm';
import { createWatcher } from '../amule-watch-session.mjs';

function harness(overrides = {}) {
  const children = [], timers = [], messages = [];
  const watcher = createWatcher({
    repoRoot: '/repo', stateDir: '/state',
    spawn(command, args, options) {
      const child = new EventEmitter();
      Object.assign(child, { stdout: new EventEmitter(), stderr: new EventEmitter(),
        kills: [], kill(sig) { this.kills.push(sig); return true; } });
      children.push({ child, command, args, options });
      return child;
    },
    setInterval(fn, ms) {
      const timer = { fn, ms, unref() { this.unreffed = true; } };
      timers.push(timer);
      return timer;
    },
    clearInterval(timer) { timer.cleared = true; },
    notify: (owner, result) => messages.push({ owner, ...result }),
    ...overrides,
  });
  const close = (code = 0, text = '', signal = null) => {
    const { child } = children.at(-1);
    child.stdout.emit('data', Buffer.from(text));
    child.emit('close', code, signal);
  };
  return { watcher, children, timers, messages, close };
}

test('explicit start alone creates hourly timer and immediate non-detached pass', async () => {
  const h = harness();
  assert.equal(h.children.length, 0);
  assert.equal(h.timers.length, 0);
  assert.equal(h.watcher.status().running, false);
  h.watcher.start('session-a');
  h.watcher.start('session-a');
  assert.equal(h.children.length, 1);
  assert.equal(h.timers.length, 1);
  assert.equal(h.timers[0].ms, 3600000);
  assert.ok(h.timers[0].unreffed);
  const run = h.children[0];
  assert.equal(run.command, 'python3');
  assert.deepEqual(run.args, ['/repo/scripts/amule-pr-watch.py', '--state-dir', '/state']);
  assert.equal(run.options.detached, false);
  assert.equal(run.options.cwd, '/repo');
  h.timers[0].fn(); // Skip overlapping checks.
  assert.equal(h.children.length, 1);
  h.close();
  assert.equal(h.messages.length, 0);
  h.timers[0].fn();
  assert.equal(h.children.length, 2);
  h.close(0, 'PR updated');
  assert.equal(h.messages[0].owner, 'session-a');
  assert.equal(h.messages[0].kind, 'findings');
  await h.watcher.stop();
});

test('run-once has no timer; errors notify; contention is not success', async () => {
  const h = harness();
  for (const [code, text, kind] of [[0, '  ', 'empty'], [7, '', 'error'],
    [75, 'watcher already running', 'contention'], [null, '', 'error']]) {
    const done = h.watcher.runOnce('a');
    h.close(code, text, code === null ? 'SIGTERM' : null);
    assert.equal((await done).kind, kind);
    assert.equal(h.watcher.status().lastResult.kind, kind);
  }
  assert.equal(h.timers.length, 0);
  assert.deepEqual(h.messages.map(m => m.kind), ['error', 'error']);
});

test('stop invalidates owner immediately, waits for close and blocks restart until reaped', async () => {
  const h = harness();
  h.watcher.start('old');
  const staleTick = h.timers[0].fn;
  let stopped = false;
  const stop = h.watcher.stop().then(() => { stopped = true; });
  const again = h.watcher.stop();
  assert.ok(h.timers[0].cleared);
  assert.deepEqual(h.children[0].child.kills, ['SIGTERM']);
  assert.throws(() => h.watcher.start('new'), /stopping/);
  staleTick();
  await Promise.resolve();
  assert.equal(stopped, false);
  h.close(0, 'late finding');
  await Promise.all([stop, again]);
  assert.equal(h.messages.length, 0);
  h.watcher.start('new');
  staleTick();
  assert.equal(h.children.length, 2);
  h.close(0, 'new finding');
  assert.equal(h.messages[0].owner, 'new');
  await h.watcher.stop();
});

test('Pi adapter is explicit, sends follow-ups and awaits lifecycle cleanup', async () => {
  const source = await readFile(new URL('../../.pi/extensions/amule-pr-watch.ts', import.meta.url), 'utf8');
  const handlers = {}, commands = {}, sent = [];
  const pi = { on: (event, fn) => { handlers[event] = fn; },
    registerCommand: (name, command) => { commands[name] = command; },
    sendMessage: (...args) => sent.push(args) };
  let h;
  // Evaluate the thin adapter with only its type annotation/imports removed.
  const factory = runInNewContext(source.replace(/^import .*;\n/gm, '')
    .replace('export default function', 'function')
    .replace('pi: ExtensionAPI', 'pi') + '\namuleWatch;', {
    createWatcher: options => { h = harness(options); return h.watcher; },
  });
  factory(pi);
  assert.equal(h.children.length, 0);
  assert.equal(h.timers.length, 0);
  const ctx = { hasUI: true, ui: { notify() {} },
    sessionManager: { getSessionId: () => 'pi-session' } };
  const command = commands['amule-watch'].handler;
  await command('status', ctx);
  await command('invalid', ctx);
  assert.equal(h.children.length, 0);
  await command('start', ctx);
  h.close(0, 'updated PR');
  assert.equal(sent.length, 1);
  assert.equal(sent[0][1].deliverAs, 'followUp');
  assert.equal(sent[0][1].triggerTurn, true);
  for (const event of ['session_before_switch', 'session_before_fork',
    'session_before_tree', 'session_shutdown']) {
    await command('start', ctx);
    h.timers.at(-1).fn();
    const cleanup = handlers[event]({}, ctx);
    h.close(0, 'stale');
    await cleanup;
    assert.equal(h.watcher.status().running, false);
  }
  assert.equal(sent.length, 1);
  const once = command('run-once', ctx);
  h.close(0);
  await once;
  assert.equal(h.watcher.status().running, false);
  await command('stop', ctx);
});

test('real Python runner is terminated and reaped by controller stop', async () => {
  const fixtures = new URL('./.amule-pr-watch-fixtures/', import.meta.url);
  await mkdir(fixtures, { recursive: true });
  const stateDir = await mkdtemp(fileURLToPath(fixtures) + 'node-');
  const messages = [];
  let child;
  const watcher = createWatcher({ stateDir,
    spawn: (...args) => { child = spawn(...args); return child; },
    notify: (...args) => messages.push(args),
  });
  try {
    await writeFile(`${stateDir}/check.sh`,
      `echo ready > '${stateDir}/ready'; (sleep 0.8; echo leaked > '${stateDir}/leaked') & wait`);
    void watcher.runOnce('integration');
    let ready = false;
    for (let i = 0; i < 500 && !ready; i++) {
      ready = await readFile(`${stateDir}/ready`).then(() => true, () => false);
      if (!ready) await delay(10);
    }
    assert.ok(ready, 'checker must have started before cancellation');
    await watcher.stop();
    assert.equal(child.exitCode, 143);
    assert.equal(watcher.status().active, false);
    assert.equal(messages.length, 0);
    const record = JSON.parse(await readFile(`${stateDir}/status.json`, 'utf8'));
    assert.equal(record.returncode, 143);
    await delay(1000);
    await assert.rejects(readFile(`${stateDir}/leaked`), { code: 'ENOENT' });
  } finally {
    await watcher.stop();
    await rm(stateDir, { recursive: true, force: true });
  }
});

test('spawn failures are reported without unhandled rejections', async () => {
  const h = harness();
  const done = h.watcher.runOnce('a');
  h.children[0].child.emit('error', new Error('missing python'));
  h.close(-2);
  assert.equal((await done).kind, 'error');
  assert.match(h.messages[0].text, /missing python/);
  const broken = harness({ spawn() { throw new Error('cannot spawn'); } });
  assert.equal((await broken.watcher.runOnce('b')).kind, 'error');
});
