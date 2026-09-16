export interface Artifact { artifact_id: string; kind: string; path?: string | null; sha256?: string | null; size?: number | null; imported_at?: string | null }
export interface Parser { name: string; version: string }
export interface Reference { artifact_id: string; locator: string }
export interface Provenance {
  source_artifact: Artifact; raw_reference: Reference; parser: Parser; tool: string;
  tool_version: string | null; plugin: string | null; memory_image_id: string | null; source?: string | null; acquisition_id?: string | null;
  extraction_timestamp: string; row_index: number; raw: Record<string, unknown>;
}
export interface EventRecord {
  event_id: string; timestamp: string; timestamp_semantics?: string;
  artifact_type?: string | null; timestamp_precision?: number | null; metadata?: Record<string, unknown>;
  source: 'memory' | 'disk' | 'network'; type: string; hostname?: string | null;
  process?: { pid: number; ppid?: number | null; name?: string | null; path?: string | null;
    command_line?: string | null; creation_time?: string | null; instance_id?: string | null;
    parent_instance_id?: string | null; exit_time?: string | null; environment?: Record<string, string> } | null;
  file?: { path?: string | null; name?: string | null; sha256?: string | null; references?: string[]; size?: number | null;
    record_number?: number | null; sequence_number?: number | null; volume_id?: string | null; file_object?: string | null } | null;
  module?: { base_address: number | null; base_address_hex?: string | null; size: number | null; name?: string | null; path?: string | null } | null;
  handle?: { type: string; name?: string | null; value?: string | null; object_address?: string | null } | null;
  memory_region?: { start: string; end?: string | null; protection?: string | null; mapped_file?: string | null } | null;
  service?: { name: string; state?: string | null; binary_path?: string | null; pid?: number | null } | null;
  registry?: { artifact: string; path?: string | null; hive?: string | null } | null;
  driver?: { name?: string | null; start?: string | null } | null;
  callback?: { type: string; address: string; module?: string | null } | null;
  prefetch?: { executable: string; run_count?: number | null; execution_times: string[] } | null;
  event_log?: { event_id: number; provider: string; record_id?: number | null } | null;
  network?: { src_ip?: string | null; src_port?: number | null; dst_ip?: string | null; dst_port?: number | null;
    protocol?: string | null; state?: string | null; dns_query?: string | null; resolved_ips?: string[];
    end_time?: string | null; packet_count?: number | null; byte_count?: number | null; stream_id?: string | null;
    tls?: { sni?: string | null; version?: string | null } | null;
    http?: { method?: string | null; host?: string | null; uri?: string | null; status?: number | null } | null } | null;
  source_artifact?: Artifact | null; raw_reference?: Reference | null; parser?: Parser | null;
  provenance?: Provenance[]; raw?: Record<string, unknown> | null; attributes?: Record<string, unknown>;
}
export interface CaseRecord { case_id: string; name: string; description?: string; event_count: number; revision: number; analysis_revision: number | null }
export interface Reason { rule: string; score: number; details: string; evidence: string[] }
export interface Correlation { source_event: string; target_event: string; score: number; raw_score?: number; reasons: Reason[] }
export interface GraphNode { id: string; kind: string; label: string; event_ids: string[] }
export interface GraphEdge { id: string; source: string; target: string; kind: string; score: number | null; reasons: Reason[]; event_ids: string[]; timestamp?: string | null; provenance?: Provenance[]; support_count?: number }
export interface ParserRun { run_id: string; parser: string; plugin: string | null; source: string;
  status: 'SUCCESS' | 'FAILED' | 'UNAVAILABLE' | 'SKIPPED'; event_count: number; row_count: number;
  error: string | null; stderr: string | null; command: string[]; warnings: string[]; artifact: Artifact | null }
export interface ArtifactContext { acquisition_id: string; extracted_at: string; hostname?: string | null;
  volume_id?: string | null; recovered_directory?: string | null; timezone?: string | null; logical_path?: string | null }
export interface ImportReport { status: string; imported: number; runs: ParserRun[] }
export interface Graph { nodes: GraphNode[]; edges: GraphEdge[]; root_event_id: string | null }
export interface Analysis { status: 'completed' | 'no_matches'; event_count: number; correlation_count: number; correlations: Correlation[] }
export interface Bridge {
  request(method: 'GET' | 'POST', path: string, body?: unknown): Promise<unknown>;
  importEvents(caseId: string): Promise<{ imported: number } | null>;
  importArtifact(caseId: string, kind: string, context: ArtifactContext, format?: string): Promise<ImportReport | null>;
}
declare global { interface Window { evidenceMesh: Bridge } }
