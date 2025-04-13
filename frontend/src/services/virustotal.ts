import { 
  VTFileUploadResponse, 
  VTAnalysisResponse, 
  VTFileInfo,
  VTResult 
} from '../types/virustotal';

const VT_API_KEY = import.meta.env.VITE_VT_API_KEY || '';
console.log("VT_API_KEY", VT_API_KEY);
const VT_API_URL = 'https://www.virustotal.com/api/v3';

const headers = {
  'x-apikey': VT_API_KEY
};

export class VirusTotalService {
  private static instance: VirusTotalService;
  private pollingIntervals: Map<string, number>;

  private constructor() {
    this.pollingIntervals = new Map();
  }

  public static getInstance(): VirusTotalService {
    if (!VirusTotalService.instance) {
      VirusTotalService.instance = new VirusTotalService();
    }
    return VirusTotalService.instance;
  }

  /**
   * Upload a file to VirusTotal
   */
  async uploadFile(file: File): Promise<string> {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch(`${VT_API_URL}/files`, {
        method: 'POST',
        headers: {
          ...headers,
        },
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json();
        console.error('VirusTotal upload failed:', {
          status: response.status,
          statusText: response.statusText,
          error: errorData
        });
        throw new Error(`Upload failed: ${response.statusText}`);
      }

      const data = await response.json() as VTFileUploadResponse;
      console.log("uploadFile success:", data);
      return data.data.id;
    } catch (error) {
      console.error('Error uploading file to VirusTotal:', error);
      throw error;
    }
  }

  /**
   * Get analysis results for a file
   */
  async getAnalysis(analysisId: string): Promise<VTAnalysisResponse> {
    try {
      const response = await fetch(`${VT_API_URL}/analyses/${analysisId}`, {
        method: 'GET',
        headers
      });

      if (!response.ok) {
        const errorData = await response.json();
        console.error('VirusTotal analysis fetch failed:', {
          status: response.status,
          statusText: response.statusText,
          analysisId,
          error: errorData
        });
        throw new Error(`Analysis fetch failed: ${response.statusText}`);
      }

      return await response.json() as VTAnalysisResponse;
    } catch (error) {
      console.error(`Error fetching analysis for ID ${analysisId}:`, error);
      throw error;
    }
  }

  /**
   * Get detailed file information
   */
  async getFileInfo(fileHash: string): Promise<VTFileInfo> {
    try {
      const response = await fetch(`${VT_API_URL}/files/${fileHash}`, {
        method: 'GET',
        headers
      });

      if (!response.ok) {
        const errorData = await response.json();
        console.error('VirusTotal file info fetch failed:', {
          status: response.status,
          statusText: response.statusText,
          fileHash,
          error: errorData
        });
        throw new Error(`File info fetch failed: ${response.statusText}`);
      }

      return await response.json() as VTFileInfo;
    } catch (error) {
      console.error(`Error fetching file info for hash ${fileHash}:`, error);
      throw error;
    }
  }

  /**
   * Start polling for analysis results
   */
  startPolling(analysisId: string, callback: (result: VTResult) => void, errorCallback: (error: Error) => void) {
    if (this.pollingIntervals.has(analysisId)) {
      console.log(`Polling already in progress for analysis ID: ${analysisId}`);
      return;
    }

    console.log(`Starting polling for analysis ID: ${analysisId}`);
    const interval = window.setInterval(async () => {
      try {
        const analysis = await this.getAnalysis(analysisId);
        const { attributes, id } = analysis.data;
        const { file_info } = analysis.meta;

        if (attributes.status === 'completed') {
          console.log(`Analysis completed for ID: ${analysisId}`);
          const fileInfo = await this.getFileInfo(file_info.sha256);
          const result = this.transformToVTResult(analysis, fileInfo);
          
          callback(result);
          this.stopPolling(analysisId);
        } else if (attributes.status === 'failed') {
          console.error(`Analysis failed for ID: ${analysisId}`);
          throw new Error('Analysis failed');
        } else {
          console.log(`Analysis status for ID ${analysisId}: ${attributes.status}`);
        }
      } catch (error) {
        console.error(`Polling error for analysis ID ${analysisId}:`, error);
        errorCallback(error as Error);
        this.stopPolling(analysisId);
      }
    }, 5000);

    this.pollingIntervals.set(analysisId, interval);
  }

  /**
   * Stop polling for a specific analysis
   */
  stopPolling(analysisId: string) {
    const interval = this.pollingIntervals.get(analysisId);
    if (interval) {
      window.clearInterval(interval);
      this.pollingIntervals.delete(analysisId);
    }
  }

  /**
   * Transform API responses into a unified result
   */
  private transformToVTResult(analysis: VTAnalysisResponse, fileInfo: VTFileInfo): VTResult {
    const { attributes: analysisAttrs } = analysis.data;
    const { attributes: fileAttrs } = fileInfo.data;
    
    const engineResults: { [key: string]: any } = {};
    Object.entries(analysisAttrs.results).forEach(([engine, result]) => {
      engineResults[engine] = {
        detected: result.category === 'malicious' || result.category === 'suspicious',
        version: result.engine_version,
        result: result.result,
        update: result.engine_update
      };
    });

    const signatureInfo = fileAttrs.signature_info ? {
      product: fileAttrs.signature_info.product,
      description: fileAttrs.signature_info.description,
      copyright: fileAttrs.signature_info.copyright,
      originalName: fileAttrs.signature_info.original_name,
      internalName: fileAttrs.signature_info.internal_name,
      fileVersion: fileAttrs.signature_info.file_version,
      company: fileAttrs.signature_info.company
    } : undefined;

    const peInfo = fileAttrs.pe_info ? {
      imphash: fileAttrs.pe_info.imphash,
      timestamp: new Date(fileAttrs.pe_info.timestamp * 1000),
      sections: fileAttrs.pe_info.sections.map(section => ({
        name: section.name,
        virtualSize: section.virtual_size,
        rawSize: section.raw_size,
        entropy: section.entropy,
        md5: section.md5
      })),
      imports: fileAttrs.pe_info.imports,
      exports: fileAttrs.pe_info.exports
    } : undefined;

    return {
      scanId: analysis.data.id,
      sha256: fileAttrs.sha256,
      sha1: fileAttrs.sha1,
      md5: fileAttrs.md5,
      date: new Date(fileAttrs.first_submission_date * 1000),
      fileName: fileAttrs.meaningful_name,
      fileSize: fileAttrs.size,
      fileType: fileAttrs.type_description,
      uploadDate: new Date(fileAttrs.first_submission_date * 1000),
      status: 'completed',
      stats: analysisAttrs.stats,
      detectionRatio: {
        detected: analysisAttrs.stats.malicious + analysisAttrs.stats.suspicious,
        total: Object.keys(analysisAttrs.results).length
      },
      engineResults,
      fileInfo: {
        magic: fileAttrs.magic,
        type: fileAttrs.type_tag,
        reputation: fileAttrs.reputation,
        firstSeen: new Date(fileAttrs.first_submission_date * 1000),
        timesSubmitted: fileAttrs.times_submitted,
        communityVotes: fileAttrs.total_votes,
        signature: signatureInfo,
        peInfo
      },
      permalink: `https://www.virustotal.com/gui/file/${fileAttrs.sha256}/detection`
    };
  }
}

export const virusTotalService = VirusTotalService.getInstance(); 