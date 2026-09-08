import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';
import { createWatcher } from '../../scripts/amule-watch-session.mjs';

// /reload to discover; /amule-watch start opts this session in. Never autostart.
export default function amuleWatch(pi: ExtensionAPI) {
  const watcher = createWatcher({
    notify(sessionId, result) {
      pi.sendMessage({
        customType: 'amule-pr-watch',
        content: `aMule watcher ${result.kind} (exit ${result.code ?? result.signal}):\n${result.text}`,
        display: true,
        details: { sessionId, kind: result.kind, code: result.code },
      }, { deliverAs: 'followUp', triggerTurn: true });
    },
  });
  const stop = async () => { await watcher.stop(); };
  pi.on('session_before_switch', stop);
  pi.on('session_before_fork', stop);
  pi.on('session_before_tree', stop);
  pi.on('session_shutdown', stop);

  pi.registerCommand('amule-watch', {
    description: 'Session-only PR watcher: start | stop | status | run-once',
    handler: async (args, ctx) => {
      const action = args.trim();
      if (!['start', 'stop', 'status', 'run-once'].includes(action)) {
        if (ctx.hasUI) ctx.ui.notify('Usage: /amule-watch start|stop|status|run-once', 'info');
        return;
      }
      try {
        const sessionId = ctx.sessionManager.getSessionId();
        if (action === 'start') watcher.start(sessionId);
        if (action === 'stop') await watcher.stop();
        if (action === 'run-once') {
          // Return promptly: stop/session changes must remain available during a run.
          void watcher.runOnce(sessionId);
        }
        const state = watcher.status();
        if (ctx.hasUI) ctx.ui.notify(
          `aMule watcher: ${state.running ? 'hourly' : 'timer off'}; ` +
          `${state.active ? 'checking' : 'idle'}; last=${state.lastResult?.kind ?? 'not checked'}; ` +
          `state=${state.stateDir}`, 'info');
      } catch (error) {
        if (ctx.hasUI) ctx.ui.notify(String(error), 'error');
      }
    },
  });
}
