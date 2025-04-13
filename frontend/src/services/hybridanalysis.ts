import axios from 'axios';

const HA_API_KEY = "inqxudolb75271d23tqp2162400fcbddnd24z5bh02413b0epxxwajdn565f0a4a";
const HA_API_URL = 'http://localhost:9002/api/v2'; // Goes through your local proxy
const USER_AGENT = 'akesherwani900@gmail.com';

interface HASubmissionResponse {
  job_id: string;
  sha256: string;
  state: string;
}

interface HADetailedReport {
  summary?: any;
  state?: string;
  screenshots?: string[];
  droppedFiles?: any[];
  memoryDumps?: any[];
  certificate?: any;
  children?: any[];
}

export interface HAResult {
  scanId: string;
  sha256: string;
  state: string;
  verdict: string;
  threatScore: number;
  malwareFamily?: string;
  environmentId: number;
  environmentDescription: string;
  startTime: Date;
  duration: number;
  signatures: Array<{
    name: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    category: string;
  }>;
  processes: Array<{
    name: string;
    pid: number;
    commandLine: string;
    isMalicious: boolean;
  }>;
  networkConnections: Array<{
    protocol: string;
    destination: string;
    port: number;
    isMalicious: boolean;
  }>;
  droppedFiles: Array<{
    name: string;
    type: string;
    hash: string;
    isMalicious: boolean;
  }>;
  mitreTactics: Array<{
    id: string;
    name: string;
    description: string;
  }>;
}

export class HybridAnalysisService {
  private static instance: HybridAnalysisService;
  private pollingIntervals: Map<string, number>;

  private constructor() {
    this.pollingIntervals = new Map();
  }

  public static getInstance(): HybridAnalysisService {
    if (!HybridAnalysisService.instance) {
      HybridAnalysisService.instance = new HybridAnalysisService();
    }
    return HybridAnalysisService.instance;
  }

  private async makeApiRequest<T>(endpoint: string, method: 'GET' | 'POST' = 'GET', data?: any): Promise<T> {
    try {
      const response = await axios({
        method,
        url: `${HA_API_URL}${endpoint}`,
        data,
        headers: {
          'api-key': HA_API_KEY,
          'User-Agent': USER_AGENT,
          'Content-Type': 'application/json',
        }
      });
      return response.data;
    } catch (error: any) {
      console.error(`Hybrid Analysis API request failed for ${endpoint}:`, error.response?.data || error.message);
      throw error;
    }
  }

  async uploadFile(file: File): Promise<string> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('environment_id', '140'); // Windows 10 64-bit

    try {
      const response = await axios.post<HASubmissionResponse>(
        `${HA_API_URL}/submit/file`,
        formData,
        {
          headers: {
            'api-key': HA_API_KEY,
            'User-Agent': USER_AGENT
            // Leave out Content-Type so browser sets boundary correctly
          }
        }
      );

      console.log('File submitted to Hybrid Analysis successfully');
      return response.data.job_id;
    } catch (error: any) {
      console.error('Hybrid Analysis submission failed:', error.response?.data || error.message);
      throw error;
    }
  }

  async getDetailedAnalysis(jobId: string): Promise<HADetailedReport> {
    const report: HADetailedReport = {};
    try {
      report.summary = await this.makeApiRequest(`/report/${jobId}/summary`);
      report.state = await this.makeApiRequest(`/report/${jobId}/state`);
      return report;
    } catch (error) {
      console.error('Failed to fetch Hybrid Analysis detailed report');
      throw error;
    }
  }

  startPolling(jobId: string, callback: (result: HAResult) => void, errorCallback: (error: Error) => void) {
    if (this.pollingIntervals.has(jobId)) {
      console.log(`Polling already in progress for job ID: ${jobId}`);
      return;
    }

    console.log(`Starting polling for job ID: ${jobId}`);
    const interval = window.setInterval(async () => {
      try {
        const report = await this.getDetailedAnalysis(jobId);

        if (report.state === 'completed') {
          console.log(`Analysis completed for job ID: ${jobId}`);
          const result = this.transformToHAResult(report);
          callback(result);
          this.stopPolling(jobId);
        } else if (report.state === 'failed') {
          throw new Error('Analysis failed');
        } else {
          console.log(`Analysis status for job ID ${jobId}: ${report.state}`);
        }
      } catch (error) {
        console.error(`Polling error for job ID ${jobId}:`, error);
        errorCallback(error as Error);
        this.stopPolling(jobId);
      }
    }, 10000); // Poll every 10 seconds

    this.pollingIntervals.set(jobId, interval);
  }

  stopPolling(jobId: string) {
    const interval = this.pollingIntervals.get(jobId);
    if (interval) {
      window.clearInterval(interval);
      this.pollingIntervals.delete(jobId);
    }
  }

  private transformToHAResult(report: HADetailedReport): HAResult {
    const summary = report.summary || {};

    return {
      scanId: summary.job_id || '',
      sha256: summary.sha256 || '',
      state: report.state || '',
      verdict: summary.verdict || 'unknown',
      threatScore: summary.threat_score || 0,
      malwareFamily: summary.malware_family,
      environmentId: summary.environment_id || 140,
      environmentDescription: summary.environment_description || 'Windows 10 64-bit',
      startTime: new Date(summary.start_time || Date.now()),
      duration: summary.duration || 0,
      signatures: (summary.signatures || []).map((sig: any) => ({
        name: sig.name,
        description: sig.description,
        severity: sig.severity,
        category: sig.category
      })),
      processes: (summary.processes || []).map((proc: any) => ({
        name: proc.name,
        pid: proc.pid,
        commandLine: proc.commandLine,
        isMalicious: proc.isMalicious || false
      })),
      networkConnections: (summary.network || []).map((conn: any) => ({
        protocol: conn.protocol,
        destination: conn.destination,
        port: conn.port,
        isMalicious: conn.isMalicious || false
      })),
      droppedFiles: (summary.dropped_files || []).map((file: any) => ({
        name: file.name,
        type: file.type,
        hash: file.hash,
        isMalicious: file.isMalicious || false
      })),
      mitreTactics: (summary.mitre_attacks || []).map((tactic: any) => ({
        id: tactic.id,
        name: tactic.name,
        description: tactic.description
      }))
    };
  }
}

export const hybridAnalysisService = HybridAnalysisService.getInstance();