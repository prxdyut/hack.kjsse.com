import express from 'express';
import { MCPClient } from './client.js';
import readline from 'readline/promises';

const app = express();
const port = process.env.PORT || 3000;
const mcpClient = new MCPClient();

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Define routes
app.get('/', (req, res) => {
  res.json({ message: 'MCP Client API is running' });
});

// Add a route to process queries
app.post('/query', async (req, res) => {
  try {
    const { query } = req.body;
    
    if (!query) {
      return res.status(400).json({ error: 'Query is required' });
    }
    
    const result = await mcpClient.processQuery(query);
    res.json({ result });
  } catch (error) {
    console.error('Error processing query:', error);
    res.status(500).json({ error: 'Failed to process query' });
  }
});

// Add a route to connect to the server
app.post('/connect', async (req, res) => {
  try {
    const { serverScriptPath } = req.body;
    
    if (!serverScriptPath) {
      return res.status(400).json({ error: 'Server script path is required' });
    }
    
    await mcpClient.connectToServer(serverScriptPath);
    res.json({ message: 'Connected to server successfully' });
  } catch (error) {
    console.error('Error connecting to server:', error);
    res.status(500).json({ error: 'Failed to connect to server' });
  }
});

// Start server and prompt for server script
async function startServer() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    // // Ask for server script path
    // const serverScriptPath = await rl.question('Enter the path to the MCP server script (.js or .py): ');
    
    // // Connect to the server
    // await mcpClient.connectToServer(serverScriptPath);
    
    // Start the Express server
    app.listen(port, () => {
      console.log(`MCP Client API running on port ${port}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  } finally {
    rl.close();
  }
}

// Handle cleanup on exit
process.on('SIGINT', async () => {
  console.log('Shutting down...');
  await mcpClient.cleanup();
  process.exit(0);
});

// Start the server
startServer();
