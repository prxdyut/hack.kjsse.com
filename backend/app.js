const http = require('http');
const httpProxy = require('http-proxy');
const https = require('https');

// Proxy with a custom agent (disable SSL check in dev)
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: false, // Disable SSL verification (for dev)
  agent: new https.Agent({ rejectUnauthorized: false }), // Disable SSL certificate check
  followRedirects: false, // Stop automatic redirect
  autoRewrite: true // Allow automatic URL rewriting (if needed)
});

// Define your default API key and User-Agent
const DEFAULT_API_KEY = "l7vkopps3f4333bfa0h7hfb288fd5bda4g0i621ab8368ab732bovooqf4a78991";
const DEFAULT_USER_AGENT = 'akesherwani900@gmail.com';

// Target API URL
const target = 'https://www.hybrid-analysis.com';

// Proxy server
http.createServer((req, res) => {
  // Handle CORS preflight request (for handling OPTIONS)
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, api-key',
    });
    res.end();
    return;
  }

  // Add CORS header for all responses
  res.setHeader('Access-Control-Allow-Origin', '*');

  // Attach the default API key and User-Agent to the request headers before sending it
  req.headers['api-key'] = DEFAULT_API_KEY;
  req.headers['User-Agent'] = DEFAULT_USER_AGENT;

  // Forward the request to the target API via proxy
  proxy.web(req, res, {
    target,
    selfHandleResponse: false, // Let the proxy handle it normally
  }, (err) => {
    console.error('Proxy error:', err.message);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Proxy error: ' + err.message);
  });
}).listen(9002, () => {
  console.log(`Proxy server running at http://localhost:9002 -> ${target}`);
});
