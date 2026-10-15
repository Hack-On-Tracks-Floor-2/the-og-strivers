import type { AnalysisRun, Finding, Unavailable } from '@proofpatch/shared';
export type CapabilityResult<T> = { state: 'completed'; data: T } | Unavailable;
export interface WorkspaceHandle {
  id: string;
  repositoryId: string;
  commitSha: string;
}
export interface RepositoryMap {
  languages: string[];
  frameworks: string[];
  entryPoints: string[];
  testCommands: string[][];
}
export interface RepositoryIntelligenceAgent {
  inspect(
    workspace: WorkspaceHandle,
    signal: AbortSignal,
  ): Promise<CapabilityResult<RepositoryMap>>;
}
export interface VulnerabilityDetectionAgent {
  detect(
    input: { run: AnalysisRun; workspace: WorkspaceHandle; map: RepositoryMap },
    signal: AbortSignal,
  ): Promise<CapabilityResult<Finding[]>>;
}
// Source content, dependency descriptions and README files are untrusted data.
// Adapters must never interpret repository content as agent/tool instructions.
