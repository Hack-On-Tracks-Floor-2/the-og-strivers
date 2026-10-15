import { useEffect, useState } from 'react';
import { RunEventSchema, type RunEvent } from '@proofpatch/shared';

export interface LiveContainer {
  image: string;
  argv: string[];
  network: 'none' | 'bridge';
  memoryMb: number;
  cpus: number;
  startedAt: string;
  finishedAt?: string;
  exitCode?: number;
  timedOut?: boolean;
}
export interface RunStream {
  events: RunEvent[];
  lines: string[];
  container?: LiveContainer;
  connected: boolean;
}

/**
 * Subscribes to /api/runs/:id/stream (Server-Sent Events): recorded history, then live events,
 * the sandbox container that is running and its output. EventSource reconnects by itself; the
 * server resends history and the recent output buffer on every (re)connect.
 */
export function useRunStream(runId: string | undefined): RunStream {
  const [state, setState] = useState<RunStream>({ events: [], lines: [], connected: false });
  useEffect(() => {
    setState({ events: [], lines: [], connected: false });
    if (!runId) return;
    const source = new EventSource(`/api/runs/${runId}/stream`, { withCredentials: true });
    source.onopen = () => setState((s) => ({ ...s, connected: true }));
    source.onerror = () => setState((s) => ({ ...s, connected: false }));
    source.onmessage = (message) => {
      const data = JSON.parse(message.data) as
        | { type: 'history'; events: unknown[] }
        | { type: 'event'; event: unknown }
        | { type: 'container'; container: LiveContainer }
        | { type: 'log'; lines: string[]; replayed?: boolean };
      setState((s) => {
        switch (data.type) {
          case 'history':
            return { ...s, events: data.events.map((e) => RunEventSchema.parse(e)) };
          case 'event': {
            const event = RunEventSchema.parse(data.event);
            return s.events.some((e) => e.id === event.id) ? s : { ...s, events: [...s.events, event] };
          }
          case 'container':
            return { ...s, container: data.container };
          case 'log': {
            const lines = data.replayed ? data.lines : [...s.lines, ...data.lines];
            return { ...s, lines: lines.slice(-800) };
          }
          default:
            return s;
        }
      });
    };
    return () => source.close();
  }, [runId]);
  return state;
}
