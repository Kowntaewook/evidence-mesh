import { contextBridge, ipcRenderer } from 'electron';
import type { Bridge } from './types';

const bridge: Bridge = {
  request: (method, path, body) => ipcRenderer.invoke('api:request', method, path, body),
  importEvents: (caseId) => ipcRenderer.invoke('evidence:import', caseId),
  importArtifact: (caseId, kind, context, format) => ipcRenderer.invoke('artifact:import', caseId, kind, context, format),
  startMemoryAnalysis: (caseId, options) => ipcRenderer.invoke('memory:analyze', caseId, options),
  inspectDiskImage: (caseId, context) => ipcRenderer.invoke('disk:inspect', caseId, context),
  selectTLSKeylog: () => ipcRenderer.invoke('network:select-keylog'),
};
contextBridge.exposeInMainWorld('evidenceMesh', bridge);
