// VirusTotal API Response Types

export interface VTFileUploadResponse {
  data: {
    id: string;
    type: string;
    links: {
      self: string;
    };
  };
}

export interface VTAnalysisStats {
  harmless: number;
  type_unsupported: number;
  suspicious: number;
  confirmed_timeout: number;
  timeout: number;
  failure: number;
  malicious: number;
  undetected: number;
}

export interface VTAnalysisAttributes {
  date: number;
  status: string;
  stats: VTAnalysisStats;
  results: {
    [engine: string]: {
      category: string;
      engine_name: string;
      engine_version: string | null;
      engine_update: string | null;
      method: string;
      result: string | null;
    };
  };
}

export interface VTAnalysisResponse {
  data: {
    attributes: VTAnalysisAttributes;
    id: string;
    type: string;
    links: {
      item: string;
      self: string;
    };
  };
  meta: {
    file_info: {
      sha256: string;
      sha1: string;
      md5: string;
      size: number;
    };
  };
}

export interface VTFileInfo {
  data: {
    attributes: {
      type_description: string;
      tlsh: string;
      size: number;
      reputation: number;
      last_modification_date: number;
      last_analysis_stats: VTAnalysisStats;
      last_analysis_results: {
        [engine: string]: {
          category: string;
          engine_name: string;
          engine_version: string | null;
          result: string | null;
          method: string;
          engine_update: string | null;
        };
      };
      magic: string;
      first_submission_date: number;
      times_submitted: number;
      total_votes: {
        harmless: number;
        malicious: number;
      };
      sha256: string;
      sha1: string;
      md5: string;
      names: string[];
      type_tag: string;
      type_extension: string;
      meaningful_name: string;
      signature_info?: {
        product: string;
        description: string;
        copyright: string;
        original_name: string;
        internal_name: string;
        file_version: string;
        company: string;
      };
      pe_info?: {
        imphash: string;
        machine_type: number;
        timestamp: number;
        entry_point: number;
        sections: {
          name: string;
          virtual_size: number;
          raw_size: number;
          entropy: number;
          md5: string;
        }[];
        imports: {
          [library: string]: string[];
        };
        exports?: string[];
      };
    };
    type: string;
    id: string;
    links: {
      self: string;
    };
  };
}

// Combined result type for the frontend
export interface VTResult {
  scanId: string;
  sha256: string;
  sha1: string;
  md5: string;
  date: Date;
  fileName: string;
  fileSize: number;
  fileType: string;
  uploadDate: Date;
  status: 'scanning' | 'completed' | 'error';
  stats: VTAnalysisStats;
  detectionRatio?: {
    detected: number;
    total: number;
  };
  engineResults: {
    [engine: string]: {
      detected: boolean;
      version: string | null;
      result: string | null;
      update: string | null;
    };
  };
  fileInfo?: {
    magic: string;
    type: string;
    reputation: number;
    firstSeen: Date;
    timesSubmitted: number;
    communityVotes: {
      harmless: number;
      malicious: number;
    };
    signature?: {
      product: string;
      description: string;
      copyright: string;
      originalName: string;
      internalName: string;
      fileVersion: string;
      company: string;
    };
    peInfo?: {
      imphash: string;
      timestamp: Date;
      sections: {
        name: string;
        virtualSize: number;
        rawSize: number;
        entropy: number;
        md5: string;
      }[];
      imports: {
        [library: string]: string[];
      };
      exports?: string[];
    };
  };
  permalink: string;
} 