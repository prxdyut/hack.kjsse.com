import axios from 'axios';
import * as fs from 'fs';
import * as FormData from 'form-data';

const API_KEY = 'f8606f78e8dd5dbd97de5091d4d0ca1bc6f04248ecd89e8d6920bf5663f09555';
const FILE_PATH = '/home/hack.kjsse.com/mcp-servers/brave-search/eicar.txt';

async function scanFile() {
  const form = new FormData();
  form.append('file', fs.createReadStream(FILE_PATH));

  try {
    // Step 1: Upload file
    const uploadResponse = await axios.post(
      'https://www.virustotal.com/api/v3/files',
      form,
      {
        headers: {
          ...form.getHeaders(),
          'x-apikey': API_KEY
        }
      }
    );

    const fileId = uploadResponse.data.data.id;
    console.log(`File uploaded. ID: ${fileId}`);

    // Step 2: Poll for report
    const reportUrl = `https://www.virustotal.com/api/v3/analyses/${fileId}`;

    let status = '';
    do {
      const reportResponse = await axios.get(reportUrl, {
        headers: { 'x-apikey': API_KEY }
      });

      status = reportResponse.data.data.attributes.status;
      if (status === 'completed') {
        const stats = reportResponse.data.data.attributes.stats;
        console.log('Scan complete:', stats);
        return stats;
      } else {
        console.log('Scanning... waiting 5s');
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    } while (status !== 'completed');

  } catch (error: any) {
    console.error('Error scanning file:', error.response?.data || error.message);
  }
}

scanFile();
