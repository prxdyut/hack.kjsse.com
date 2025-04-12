# MCP Client Server

An Express.js server that connects to an MCP server and provides an API to interact with it.

## Setup

1. Make sure you have Node.js installed
2. Install dependencies:
   ```
   npm install
   ```
3. Create a `.env` file in the project root with your Anthropic API key:
   ```
   ANTHROPIC_API_KEY=your_api_key_here
   ```

## Usage

### Development mode

```
npm run dev:server
```

### Production mode

```
npm run start:server
```

When the server starts, it will prompt you to enter the path to your MCP server script (.js or .py file).

## API Endpoints

- `GET /`: Health check endpoint
- `POST /query`: Send a query to the MCP client
  - Request body: `{ "query": "your query text" }`
  - Response: `{ "result": "processed result" }`

## Example

```bash
# Start the server
npm run dev:server

# When prompted, enter the path to your MCP server script:
# Enter the path to the MCP server script (.js or .py): ../mcp-servers/src/memory/memory.js

# The server will connect to the MCP server and start listening on port 3000
```

You can then send queries to the API:

```bash
curl -X POST http://localhost:3000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What can you do?"}'
``` 