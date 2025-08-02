const http = require('http');
const url = require('url');

// MCPメッセージのIDカウンター
let messageId = 1;

// レスポンスヘルパー関数
function sendJsonResponse(res, data, statusCode = 200) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  });
  res.end(JSON.stringify(data));
}

// MCPプロトコルメッセージハンドラー
function handleMCPMessage(message) {
  const { method, params } = message;

  switch (method) {
    case 'initialize':
      return {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: {
            tools: {},
            prompts: {},
            resources: {}
          },
          serverInfo: {
            name: 'hello-world-mcp-server',
            version: '1.0.0'
          }
        }
      };

    case 'notifications/initialized':
      // initialized通知には応答不要
      return null;

    case 'tools/list':
      return {
        jsonrpc: '2.0',
        id: message.id,
        result: {
          tools: [
            {
              name: 'hello_world',
              description: 'Returns a simple hello world message',
              inputSchema: {
                type: 'object',
                properties: {
                  name: {
                    type: 'string',
                    description: 'Name to greet (optional)'
                  }
                }
              }
            }
          ]
        }
      };

    case 'tools/call':
      const { name: toolName, arguments: args } = params;
      
      if (toolName === 'hello_world') {
        const name = args?.name || 'World';
        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [
              {
                type: 'text',
                text: `Hello, ${name}! This is a simple MCP server response.`
              }
            ]
          }
        };
      }
      
      // 未知のツール
      return {
        jsonrpc: '2.0',
        id: message.id,
        error: {
          code: -32601,
          message: `Unknown tool: ${toolName}`
        }
      };

    default:
      return {
        jsonrpc: '2.0',
        id: message.id,
        error: {
          //code: -32601,
          //message: `Method not found: ${method}`
        }
      };
  }
}

// HTTPサーバー作成
const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  
  // CORS preflight
  if (req.method === 'OPTIONS') {
    sendJsonResponse(res, {});
    return;
  }

  // GET - サーバー情報
  if (req.method === 'GET' && parsedUrl.pathname === '/') {
    sendJsonResponse(res, {
      name: 'Hello World MCP Server',
      version: '1.0.0',
      description: 'A simple MCP server that responds with hello world messages',
      endpoints: {
        mcp: '/mcp'
      }
    });
    return;
  }

  // POST - MCPメッセージ処理
  if (req.method === 'POST' && parsedUrl.pathname === '/mcp') {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', () => {
      try {
        const message = JSON.parse(body);
        console.log('Received MCP message:', JSON.stringify(message, null, 2));
        
        const response = handleMCPMessage(message);
        
        if (response) {
          console.log('Sending response:', JSON.stringify(response, null, 2));
          sendJsonResponse(res, response);
        } else {
          // notifications/initializedなど、応答不要の場合
          res.writeHead(204);
          res.end();
        }
      } catch (error) {
        console.error('Error processing message:', error);
        sendJsonResponse(res, {
          jsonrpc: '2.0',
          id: null,
          error: {
            code: -32700,
            message: 'Parse error'
          }
        }, 400);
      }
    });
    return;
  }

  // 404
  sendJsonResponse(res, { error: 'Not found' }, 404);
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`MCP HTTP Server running on port ${PORT}`);
  console.log(`Server info: http://localhost:${PORT}/`);
  console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
});

// グレースフルシャットダウン
process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});