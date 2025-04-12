// falconScan.ts
import axios from 'axios';
import * as fs from 'fs';
import * as path from 'path';
import FormData from 'form-data';

const API_KEY = 'r3zgt6xjc70f3ed2hbygipsc619490049fy7cse04798212div21yd1wa60097f5';
const USER_AGENT = 'daspradyut516@gmail.com';
const FILE_PATH = path.resolve(__dirname, '35eb3565230ddcb9dc531104f975463fcd4bae691c38ac9fd468de49cb7e590e.zip');
const BASE_URL = 'https://www.hybrid-analysis.com/api/v2';

// Optional submission metadata
const ENVIRONMENT_ID = 140; // 300 = Windows 10 64-bit

// Response type for Falcon Sandbox
interface SubmissionResponse {
  data_id: string;
  type: string;
  state: string;
  sha256: string;
  job_id: string;
}

interface DetailedReport {
  summary?: any;
  state?: string;
  screenshots?: string[];
  droppedFiles?: any[];
  memoryDumps?: any[];
  certificate?: any;
  children?: any[];
}

// Generic API request function with error handling
async function makeApiRequest<T>(endpoint: string, method: 'GET' | 'POST' = 'GET', data?: any): Promise<T> {
  try {
    const response = await axios({
      method,
      url: `${BASE_URL}${endpoint}`,
      headers: {
        'api-key': API_KEY,
        'User-Agent': USER_AGENT,
      },
      data,
    });
    return response.data;
  } catch (error: any) {
    console.error(`❌ API request failed for ${endpoint}:`, JSON.stringify(error.response?.data, null, 2) || error.message);
    throw error;
  }
}

// Upload a file to Falcon Sandbox
async function uploadToFalcon(filePath: string): Promise<SubmissionResponse> {
  const form = new FormData();
  form.append('file', fs.createReadStream(filePath));
  form.append('environment_id', ENVIRONMENT_ID.toString());

  try {
    const response = await axios.post<SubmissionResponse>(
      `${BASE_URL}/submit/file`,
      form,
      {
        headers: {
          ...form.getHeaders(),
          'api-key': API_KEY,
          'User-Agent': USER_AGENT,
        },
      }
    );

    console.log('✅ File submitted successfully.');
    return response.data;
  } catch (error: any) {
    console.error('❌ Submission failed:', JSON.stringify(error.response?.data, null, 2) || error.message);
    throw error;
  }
}

// Get detailed analysis report
async function getDetailedAnalysis(id: string): Promise<DetailedReport> {
  const report: DetailedReport = {};

  try {
    // Get summary
    report.summary = await makeApiRequest(`/report/${id}/summary`);
    console.log('📊 Summary report fetched');

    // Get state
    report.state = await makeApiRequest(`/report/${id}/state`);
    console.log('📌 Analysis state fetched');

    // Get screenshots
    // report.screenshots = await makeApiRequest(`/report/${id}/screenshots`);
    // console.log('📸 Screenshots fetched');

    // Get dropped files
    // report.droppedFiles = await makeApiRequest(`/report/${id}/dropped-files`);
    // console.log('📦 Dropped files information fetched');

    // Get memory dumps list
    // report.memoryDumps = await makeApiRequest(`/report/${id}/memory-dumps-list`);
    // console.log('💾 Memory dumps list fetched');

    // Get certificate info
    // report.certificate = await makeApiRequest(`/report/${id}/certificate`);
    // console.log('🔐 Certificate information fetched');

    // Get children information
    // report.children = await makeApiRequest(`/report/${id}/children`);
    // console.log('👥 Children information fetched');

    return report;
  } catch (error) {
    console.error('❌ Failed to fetch detailed analysis');
    throw error;
  }
}

// Save report to file
async function saveReportToFile(report: DetailedReport, filename: string) {
  try {
    await fs.promises.writeFile(
      filename,
      JSON.stringify(report, null, 2),
      'utf-8'
    );
    console.log(`📝 Report saved to ${filename}`);
  } catch (error) {
    console.error('❌ Failed to save report:', error);
  }
}

// Main function
async function scanWithFalcon(filePath: string) {
  try {
    // Upload and get initial response
    const result = await uploadToFalcon(filePath);
    console.log('🔍 Submission Info:', result);
    console.log(`🧾 You can view the analysis at: https://www.hybrid-analysis.com/sample/${result.sha256}`);

    // Wait for a few seconds to allow initial analysis
    console.log('⏳ Waiting for analysis to begin...');
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Get detailed analysis
    console.log('📊 Fetching detailed analysis...');
    let detailedReport: any = null;
    try {
      await makeApiRequest(`/report/${result.job_id}/summary`);
      detailedReport = await getDetailedAnalysis(result.job_id);
    } catch (error: any) {
      const related_id = error.response.data.related_id[0]
      detailedReport = await getDetailedAnalysis(related_id);
    }

    // Save the report
    const reportFileName = `falcon_report_${result.sha256}.json`;
    await saveReportToFile(detailedReport, reportFileName);

    console.log('✅ Analysis complete! Check the saved report for details.');
  } catch (e) {
    console.error('❌ Failed to scan file with Falcon Sandbox.');
  }
}

scanWithFalcon(FILE_PATH);
