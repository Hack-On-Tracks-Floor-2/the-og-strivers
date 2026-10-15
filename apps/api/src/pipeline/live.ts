import { EventEmitter } from 'node:events';
import type { RunEvent } from '@proofpatch/shared';

/**
 * In-memory live channel for a running analysis: recorded events as they are written, the sandbox
 * container currently running (image + limits), and its output line by line. Nothing here is
 * persisted; the durable record stays in the database. Late subscribers get the recent buffer.
 */
export interface ContainerInfo {
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
export type LiveMessage =
  | { type: 'event'; event: RunEvent }
  | { type: 'container'; container: ContainerInfo }
  | { type: 'log'; lines: string[] };

const MAX_LINES = 600;
const strip = (s: string) => s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/\r(?!\n)/g, '\n');

export class LiveHub {
  private emitter = new EventEmitter();
  private recent = new Map<string, { lines: string[]; container?: ContainerInfo; partial: string }>();
  constructor() {
    this.emitter.setMaxListeners(100);
  }
  private state(runId: string) {
    let s = this.recent.get(runId);
    if (!s) {
      s = { lines: [], partial: '' };
      this.recent.set(runId, s);
      // Keep at most ~50 runs in memory.
      if (this.recent.size > 50) this.recent.delete(this.recent.keys().next().value!);
    }
    return s;
  }
  event(runId: string, event: RunEvent) {
    this.emitter.emit(runId, { type: 'event', event } satisfies LiveMessage);
  }
  container(runId: string, container: ContainerInfo) {
    this.state(runId).container = container;
    this.emitter.emit(runId, { type: 'container', container } satisfies LiveMessage);
  }
  /** Raw output chunk from the running container; emitted as complete lines. */
  output(runId: string, chunk: string) {
    const s = this.state(runId);
    const parts = (s.partial + strip(chunk)).split('\n');
    s.partial = parts.pop() ?? '';
    const lines = parts.map((l) => l.slice(0, 400));
    if (!lines.length) return;
    s.lines.push(...lines);
    if (s.lines.length > MAX_LINES) s.lines.splice(0, s.lines.length - MAX_LINES);
    this.emitter.emit(runId, { type: 'log', lines } satisfies LiveMessage);
  }
  /** Flushes a trailing partial line (when a container exits). */
  flush(runId: string) {
    const s = this.state(runId);
    if (s.partial) {
      const lines = [s.partial.slice(0, 400)];
      s.partial = '';
      s.lines.push(...lines);
      this.emitter.emit(runId, { type: 'log', lines } satisfies LiveMessage);
    }
  }
  snapshot(runId: string) {
    const s = this.recent.get(runId);
    return { lines: s?.lines ?? [], container: s?.container };
  }
  subscribe(runId: string, listener: (message: LiveMessage) => void) {
    this.emitter.on(runId, listener);
    return () => this.emitter.off(runId, listener);
  }
}
