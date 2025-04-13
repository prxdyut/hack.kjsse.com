// virusScan.ts
import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import FormData from 'form-data';

// Replace with your actual VirusTotal API key
const API_KEY = 'f8606f78e8dd5dbd97de5091d4d0ca1bc6f04248ecd89e8d6920bf5663f09555';
const FILE_PATH = path.resolve(__dirname, 'eicar.txt');

interface UploadResponse {
  data: {
    id: string;
  };
}

interface AnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
}

interface AnalysisResponse {
  data: {
    attributes: {
      status: 'queued' | 'in-progress' | 'completed';
      stats: AnalysisStats;
    };
  };
}

// Upload the file and return the analysis ID
async function uploadFile(filePath: string): Promise<string> {
  const form = new FormData();
  form.append('file', fs.createReadStream(filePath));

  const response = await axios.post<UploadResponse>(
    'https://www.virustotal.com/api/v3/files',
    form,
    {
      headers: {
        ...form.getHeaders(),
        'x-apikey': API_KEY,
      },
    }
  );

  const analysisId = response.data.data.id;
  console.log(`✅ File uploaded. Analysis ID: ${analysisId}`);
  return analysisId;
}

// Poll VirusTotal until the scan completes
async function waitForAnalysis(analysisId: string): Promise<AnalysisStats> {
  const url = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;

  while (true) {
    const response = await axios.get<AnalysisResponse>(url, {
      headers: { 'x-apikey': API_KEY },
    });

    const { status, stats } = response.data.data.attributes;

    if (status === 'completed') {
      console.log('✅ Scan completed.');
      return stats;
    }

    console.log('⏳ Scan in progress... retrying in 5 seconds');
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
}

// Main
async function scanFile(filePath: string) {
  try {
    const analysisId = await uploadFile(filePath);
    const scanResults = await waitForAnalysis(analysisId);

    console.log('🔍 Scan Summary:', scanResults);
  } catch (error: any) {
    console.error('❌ Error during file scan:', error.response?.data || error.message);
  }
}

scanFile(FILE_PATH);
