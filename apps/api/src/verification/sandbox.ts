import type { CapabilityResult, WorkspaceHandle } from '../agents/contracts.js';
export interface ExecutionRequest {
  workspace: WorkspaceHandle;
  argv: string[];
  timeoutMs: number;
  memoryMb: number;
  cpuLimit: number;
  network: 'none';
  readOnlyRoot: true;
  maxOutputBytes: number;
}
export interface ExecutionResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  artifactId: string;
}
export interface SandboxExecutionAdapter {
  execute(
    request: ExecutionRequest,
    signal: AbortSignal,
  ): Promise<CapabilityResult<ExecutionResult>>;
}
export class UnconfiguredSandbox implements SandboxExecutionAdapter {
  async execute(): Promise<CapabilityResult<ExecutionResult>> {
    return {
      code: 'CAPABILITY_UNAVAILABLE',
      state: 'not_configured',
      message: 'Docker sandbox integration pending. Host execution is disabled.',
    };
  }
}
