// Type definitions for the application
import { VTResult } from '../types/virustotal';

// Using CustomFile to avoid conflict with DOM File type
export interface CustomFile {
  id: string
  name: string
  size: string
  type: string
  url: string
  status: 'uploading' | 'processing' | 'completed' | 'error'
  progress?: number
  originalFile?: File // Store the original File object
  timestamp?: Date
  analysisReport?: AnalysisReport // Field for the analysis report
}

export interface Message {
  id: number
  text: string
  sender: 'user' | 'assistant'
  files?: CustomFile[]
  timestamp: Date
}

// Static Analysis Interfaces
export interface StaticAnalysis {
  scanId: string
  scanDate: Date
  detectionRate: number
  totalScans: number
  positiveScans: number
  fileInfo: FileInfo
  signatures: Signature[]
  virusTotal: VTResult // Updated to use VTResult
}

export interface FileInfo {
  md5: string
  sha1: string
  sha256: string
  fileSize: number
  fileType: string
  magic: string
  compilationTimestamp?: Date
}

export interface Signature {
  name: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  category: 'malware' | 'pup' | 'adware' | 'suspicious' | 'clean'
}

export interface VirusTotalResult {
  permalink: string
  scanDate: Date
  positives: number
  total: number
  scans: { [engine: string]: ScanResult }
}

export interface ScanResult {
  detected: boolean
  version: string
  result: string | null
  update: string
}

// Dynamic Analysis Interfaces
export interface DynamicAnalysis {
  executionId: string
  executionDate: Date
  duration: number
  summary: DynamicAnalysisSummary
  processes: Process[]
  networkActivity: NetworkActivity[]
  fileSystemActivity: FileSystemActivity[]
  registryActivity: RegistryActivity[]
}

export interface DynamicAnalysisSummary {
  riskScore: number
  verdict: 'clean' | 'suspicious' | 'malicious'
  foundMalware: boolean
  malwareFamily?: string
  behaviorCategories: string[]
  mitreTactics: MitreTactic[]
}

export interface MitreTactic {
  id: string
  name: string
  description: string
}

export interface Process {
  pid: number
  name: string
  path: string
  commandLine: string
  parentPid: number
  creationTime: Date
  isMalicious: boolean
  signature?: string
}

export interface NetworkActivity {
  processName: string
  pid: number
  protocol: 'TCP' | 'UDP' | 'HTTP' | 'DNS' | 'HTTPS'
  localIp: string
  localPort: number
  remoteIp: string
  remotePort: number
  remoteHostname?: string
  requestSize?: number
  responseSize?: number
  timestamp: Date
  isMalicious: boolean
  maliciousReason?: string
}

export interface FileSystemActivity {
  processName: string
  pid: number
  operation: 'create' | 'modify' | 'delete' | 'rename' | 'read'
  path: string
  timestamp: Date
  isMalicious: boolean
  maliciousReason?: string
}

export interface RegistryActivity {
  processName: string
  pid: number
  operation: 'create' | 'modify' | 'delete' | 'query'
  key: string
  value?: string
  data?: string
  timestamp: Date
  isMalicious: boolean
  maliciousReason?: string
}

// Combined Analysis Report
export interface AnalysisReport {
  reportId: string
  fileId: string
  fileName: string
  overallVerdict: 'clean' | 'suspicious' | 'malicious'
  threatScore: number
  staticAnalysis: StaticAnalysis
  dynamicAnalysis?: DynamicAnalysis // Optional since not all files may undergo dynamic analysis
  analyzedAt: Date
}

export type ScanLevel = 'basic' | 'deep'; 