const http = require('http');
const url = require('url');
const crypto = require('crypto');
const querystring = require('querystring');

// ダミーOAuth設定
const DUMMY_OAUTH_CONFIG = {
  clientId: 'mcp-inspector-client',
  clientSecret: 'mcp-inspector-secret',
  redirectUri: 'http://localhost:3000/oauth/callback',
  authorizationUrl: 'http://localhost:3000/oauth/authorize',
  tokenUrl: 'http://localhost:3000/oauth/token',
  userInfoUrl: 'http://localhost:3000/oauth/userinfo'
};

// ダミーユーザーデータベース
const DUMMY_USERS = {
  'inspector': {
    id: 'user-inspector',
    username: 'inspector',
    name: 'MCP Inspector User',
    email: 'inspector@mcp.test',
    password: 'inspector123'
  },
  'admin': {
    id: 'user-admin',
    username: 'admin',
    name: 'Admin User',
    email: 'admin@example.com',
    password: 'admin123'
  },
  'demo': {
    id: 'user-demo',
    username: 'demo',
    name: 'Demo User',
    email: 'demo@example.com',
    password: 'demo123'
  }
};

// セッション管理
const sessions = new Map();
const accessTokens = new Map();
const authorizationCodes = new Map();

// Dynamic Client Registration用のストレージ
const globalDynamicClients = new Map();

// ヘルパー関数
function generateRandomString(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function sendJsonResponse(res, data, statusCode = 200) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
}

function sendHtmlResponse(res, html, statusCode = 200) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(html);
}

function verifyAccessToken(token) {
  if (!token) return null;
  const tokenData = accessTokens.get(token);
  if (!tokenData) return null;
  if (Date.now() > tokenData.expiresAt) {
    accessTokens.delete(token);
    return null;
  }
  return tokenData;
}

function getUserFromToken(token) {
  const tokenData = verifyAccessToken(token);
  if (!tokenData) return null;
  
  return Object.values(DUMMY_USERS).find(u => u.id === tokenData.userId);
}

// HTTPベースの簡易認証
function handleQuickAuth(method, params) {
  switch (method) {
    case 'auth/quick_login':
      const { username, password } = params;
      const user = DUMMY_USERS[username];
      
      if (!user || user.password !== password) {
        return {
          error: {
            code: -32602,
            message: 'Invalid credentials',
            data: { 
              available_users: Object.keys(DUMMY_USERS),
              hint: 'Try: inspector/inspector123, admin/admin123, demo/demo123'
            }
          }
        };
      }

      // アクセストークン生成
      const accessToken = generateRandomString(32);
      accessTokens.set(accessToken, {
        userId: user.id,
        scope: 'read write',
        createdAt: Date.now(),
        expiresAt: Date.now() + (3600 * 1000)
      });

      return {
        result: {
          success: true,
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          user: {
            id: user.id,
            username: user.username,
            name: user.name,
            email: user.email
          }
        }
      };

    case 'auth/token_login':
      const { token } = params;
      const user2 = getUserFromToken(token);
      
      if (!user2) {
        return {
          error: {
            code: -32602,
            message: 'Invalid or expired token'
          }
        };
      }

      return {
        result: {
          success: true,
          user: {
            id: user2.id,
            username: user2.username,
            name: user2.name,
            email: user2.email
          }
        }
      };

    default:
      return null;
  }
}

// MCPメッセージハンドラー
function handleMCPMessage(message, authToken = null) {
  const { method, params } = message;

  // 簡易認証メソッドの処理
  if (method.startsWith('auth/')) {
    const authResponse = handleQuickAuth(method, params);
    if (authResponse) {
      return {
        jsonrpc: '2.0',
        id: message.id,
        ...authResponse
      };
    }
  }

  // 現在のユーザー情報取得
  const currentUser = getUserFromToken(authToken);

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
            name: 'http-oauth-mcp-server',
            version: '1.0.0',
            description: 'HTTP-based MCP Server with OAuth authentication'
          },
          // MCP Inspector向けOAuth設定
          oauth: {
            authorization_endpoint: DUMMY_OAUTH_CONFIG.authorizationUrl,
            token_endpoint: DUMMY_OAUTH_CONFIG.tokenUrl,
            client_id: DUMMY_OAUTH_CONFIG.clientId,
            redirect_uri: DUMMY_OAUTH_CONFIG.redirectUri,
            scopes: ['read', 'write']
          }
        }
      };

    case 'notifications/initialized':
      return null;

    case 'tools/list':
      const tools = [
        {
          name: 'hello_world',
          description: 'Returns a hello world message',
          inputSchema: {
            type: 'object',
            properties: {
              name: { type: 'string', description: 'Name to greet (optional)' }
            }
          }
        },
        {
          name: 'quick_login',
          description: '🔐 Quick login with username/password (inspector/inspector123, admin/admin123, demo/demo123)',
          inputSchema: {
            type: 'object',
            properties: {
              username: { type: 'string', description: 'Username' },
              password: { type: 'string', description: 'Password' }
            },
            required: ['username', 'password']
          }
        },
        {
          name: 'auth_status',
          description: 'Shows current authentication status',
          inputSchema: { type: 'object', properties: {} }
        },
        {
          name: 'available_users',
          description: 'Lists available test users for authentication',
          inputSchema: { type: 'object', properties: {} }
        }
      ];

      // 認証済みユーザー向けツール
      if (currentUser) {
        tools.push(
          {
            name: 'user_profile',
            description: 'Returns authenticated user profile',
            inputSchema: { type: 'object', properties: {} }
          },
          {
            name: 'protected_data',
            description: 'Returns protected data (requires authentication)',
            inputSchema: {
              type: 'object',
              properties: {
                category: { 
                  type: 'string', 
                  enum: ['personal', 'financial', 'admin'],
                  description: 'Category of protected data'
                }
              }
            }
          },
          {
            name: 'oauth_info',
            description: 'Shows OAuth configuration and flow information',
            inputSchema: { type: 'object', properties: {} }
          }
        );

        // 管理者専用ツール
        if (currentUser.username === 'admin' || currentUser.username === 'inspector') {
          tools.push({
            name: 'admin_panel',
            description: 'Access admin panel functions',
            inputSchema: {
              type: 'object',
              properties: {
                action: { 
                  type: 'string',
                  enum: ['list_tokens', 'revoke_token', 'user_stats'],
                  description: 'Admin action to perform'
                },
                target: { type: 'string', description: 'Target for action (if applicable)' }
              }
            }
          });
        }
      }

      return {
        jsonrpc: '2.0',
        id: message.id,
        result: { tools }
      };

    case 'tools/call':
      const { name: toolName, arguments: args } = params;
      
      if (toolName === 'quick_login') {
        const { username, password } = args;
        const user = DUMMY_USERS[username];
        
        if (!user || user.password !== password) {
          return {
            jsonrpc: '2.0',
            id: message.id,
            result: {
              content: [{
                type: 'text',
                text: `❌ Login failed for user: ${username}\n\nAvailable test users:\n${Object.entries(DUMMY_USERS).map(([u, data]) => `👤 ${u} / ${data.password}`).join('\n')}`
              }]
            }
          };
        }

        // アクセストークン生成
        const accessToken = generateRandomString(32);
        accessTokens.set(accessToken, {
          userId: user.id,
          scope: 'read write',
          createdAt: Date.now(),
          expiresAt: Date.now() + (3600 * 1000)
        });

        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [{
              type: 'text',
              text: `✅ Login successful!\n\nUser: ${user.name} (${user.username})\nAccess Token: ${accessToken}\n\n🔑 To use this token:\n1. Copy the access token above\n2. Add Authorization header: Bearer ${accessToken}\n3. Or use the token in subsequent requests\n\n🧪 Try calling other tools now - you should see new authenticated tools available!`
            }]
          }
        };
      }
      
      if (toolName === 'hello_world') {
        const name = args?.name || (currentUser?.name || 'World');
        const authStatus = currentUser ? '🔐 Authenticated' : '🔓 Anonymous';
        
        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [{
              type: 'text',
              text: `Hello, ${name}! (${authStatus})\n\nServer: HTTP MCP OAuth Server\nTimestamp: ${new Date().toISOString()}`
            }]
          }
        };
      }

      if (toolName === 'auth_status') {
        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [{
              type: 'text',
              text: `🔐 Authentication Status:\n\nCurrent User: ${currentUser ? currentUser.name + ' (' + currentUser.username + ')' : 'Anonymous'}\nAuthenticated: ${currentUser ? '✅ Yes' : '❌ No'}\nToken Present: ${authToken ? '✅ Yes' : '❌ No'}\nToken Valid: ${verifyAccessToken(authToken) ? '✅ Yes' : '❌ No'}\n\n${!currentUser ? `🔑 To authenticate:\n1. Use the 'quick_login' tool with username/password\n2. Or use Authorization header with Bearer token\n\n👥 Available test users:\n${Object.entries(DUMMY_USERS).map(([username, user]) => `   👤 ${username} / ${user.password}`).join('\n')}` : ''}`
            }]
          }
        };
      }

      if (toolName === 'available_users') {
        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [{
              type: 'text',
              text: `👥 Available Test Users:\n\n${Object.entries(DUMMY_USERS).map(([username, user]) => `👤 **${username}** / ${user.password}\n   Name: ${user.name}\n   Email: ${user.email}\n   Role: ${username === 'admin' || username === 'inspector' ? 'Admin' : 'User'}\n`).join('\n')}\n🔑 Quick Login:\nUse the 'quick_login' tool with any of these credentials!`
            }]
          }
        };
      }

      if (toolName === 'user_profile') {
        if (!currentUser) {
          return {
            jsonrpc: '2.0',
            id: message.id,
            error: {
              code: -32603,
              message: 'Authentication required. Use quick_login tool first!'
            }
          };
        }

        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [{
              type: 'text',
              text: `👤 User Profile:\n\n**Personal Information:**\n• ID: ${currentUser.id}\n• Username: ${currentUser.username}\n• Name: ${currentUser.name}\n• Email: ${currentUser.email}\n\n**Session Information:**\n• Token: ${authToken?.substring(0, 12)}...\n• Login Time: ${new Date().toISOString()}\n• Permissions: read, write${currentUser.username === 'admin' || currentUser.username === 'inspector' ? ', admin' : ''}\n\n**Available Actions:**\n${currentUser.username === 'admin' || currentUser.username === 'inspector' ? '• Access admin panel\n• View all user data\n• Manage tokens' : '• View personal data\n• Access protected content'}`
            }]
          }
        };
      }

      if (toolName === 'protected_data') {
        if (!currentUser) {
          return {
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32603, message: 'Authentication required' }
          };
        }

        const category = args?.category || 'personal';
        const protectedData = {
          personal: `📋 Personal Data for ${currentUser.name}:\n• Phone: +1-555-0${Math.floor(Math.random() * 1000).toString().padStart(3, '0')}\n• Address: ${Math.floor(Math.random() * 9999)} Main St, City\n• Birthday: 199${Math.floor(Math.random() * 10)}-0${Math.floor(Math.random() * 9) + 1}-${Math.floor(Math.random() * 28) + 1}`,
          
          financial: `💰 Financial Data for ${currentUser.name}:\n• Account Balance: $${(Math.random() * 100000).toFixed(2)}\n• Credit Score: ${Math.floor(Math.random() * 200) + 650}\n• Last Transaction: $${(Math.random() * 500).toFixed(2)} at Store XYZ`,
          
          admin: currentUser.username === 'admin' || currentUser.username === 'inspector' ? 
            `⚡ Admin Data:\n• Active Users: ${accessTokens.size}\n• Server Uptime: ${process.uptime().toFixed(0)} seconds\n• Memory Usage: ${(process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2)} MB` :
            'Access denied: Admin privileges required'
        };

        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [{
              type: 'text',
              text: `🛡️ Protected Data Access:\n\n${protectedData[category]}\n\nAccessed by: ${currentUser.name} (${currentUser.username})\nAccess Time: ${new Date().toISOString()}\nData Category: ${category}`
            }]
          }
        };
      }

      if (toolName === 'oauth_info') {
        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [{
              type: 'text',
              text: `🔐 OAuth Configuration:\n\n**OAuth Endpoints:**\n• Authorization: ${DUMMY_OAUTH_CONFIG.authorizationUrl}\n• Token: ${DUMMY_OAUTH_CONFIG.tokenUrl}\n• User Info: ${DUMMY_OAUTH_CONFIG.userInfoUrl}\n• Callback: ${DUMMY_OAUTH_CONFIG.redirectUri}\n\n**Client Configuration:**\n• Client ID: ${DUMMY_OAUTH_CONFIG.clientId}\n• Scopes: read, write\n\n**Current Status:**\n• Server: Running on HTTP\n• Transport: Standard HTTP POST\n• Authentication: ${currentUser ? 'Active' : 'None'}\n• MCP Inspector Compatible: ✅ Yes`
            }]
          }
        };
      }

      if (toolName === 'admin_panel') {
        if (!currentUser || (currentUser.username !== 'admin' && currentUser.username !== 'inspector')) {
          return {
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32603, message: 'Admin privileges required' }
          };
        }

        const action = args?.action || 'list_tokens';
        let result = '';

        switch (action) {
          case 'list_tokens':
            result = `🎫 Active Tokens:\n\n${Array.from(accessTokens.entries()).map(([token, data]) => {
              const user = Object.values(DUMMY_USERS).find(u => u.id === data.userId);
              return `• ${token.substring(0, 8)}... - ${user?.name || 'Unknown'} (expires: ${new Date(data.expiresAt).toLocaleString()})`;
            }).join('\n') || 'No active tokens'}`;
            break;
          
          case 'user_stats':
            result = `📊 User Statistics:\n\n${Object.entries(DUMMY_USERS).map(([username, user]) => 
              `• ${user.name} (${username}): ${Array.from(accessTokens.values()).filter(t => t.userId === user.id).length} active sessions`
            ).join('\n')}`;
            break;
          
          case 'revoke_token':
            const target = args?.target;
            if (target) {
              const found = Array.from(accessTokens.entries()).find(([token]) => token.startsWith(target));
              if (found) {
                accessTokens.delete(found[0]);
                result = `✅ Token ${target}... revoked successfully`;
              } else {
                result = `❌ Token ${target}... not found`;
              }
            } else {
              result = '❌ Target token prefix required';
            }
            break;
          
          default:
            result = '❌ Unknown admin action';
        }

        return {
          jsonrpc: '2.0',
          id: message.id,
          result: {
            content: [{
              type: 'text',
              text: `⚡ Admin Panel - ${action}:\n\n${result}\n\nExecuted by: ${currentUser.name}\nTimestamp: ${new Date().toISOString()}`
            }]
          }
        };
      }
      
      return {
        jsonrpc: '2.0',
        id: message.id,
        error: { code: -32601, message: `Unknown tool: ${toolName}` }
      };

    default:
      return {
        jsonrpc: '2.0',
        id: message.id,
        error: { code: -32601, message: `Method not found: ${method}` }
      };
  }
}

// OAuth エンドポイント
function handleAuthorizationEndpoint(req, res, parsedUrl) {
  const { client_id, redirect_uri, state, scope, response_type } = parsedUrl.query;
  
  // 静的クライアント または 動的クライアントをチェック
  let isValidClient = false;
  if (client_id === DUMMY_OAUTH_CONFIG.clientId) {
    isValidClient = true;
  } else if (globalDynamicClients.has(client_id)) {
    const dynamicClient = globalDynamicClients.get(client_id);
    if (dynamicClient.redirect_uris.includes(redirect_uri)) {
      isValidClient = true;
    }
  }

  if (!isValidClient) {
    sendHtmlResponse(res, '<h1>Error: Invalid client_id or redirect_uri</h1>', 400);
    return;
  }

  const loginForm = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>MCP OAuth Login</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        .user-list { background: #f8f9fa; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .client-info { background: #e3f2fd; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 12px; }
      </style>
    </head>
    <body>
      <h2>🔐 MCP OAuth Login</h2>
      
      <div class="client-info">
        <strong>Client:</strong> ${client_id}<br>
        <strong>Scope:</strong> ${scope || 'read write'}
      </div>
      
      <div class="user-list">
        <h4>Test Users:</h4>
        ${Object.entries(DUMMY_USERS).map(([username, user]) => 
          `<div>👤 ${username} / ${user.password}</div>`
        ).join('')}
      </div>

      <form method="POST" action="/oauth/authorize">
        <input type="hidden" name="client_id" value="${client_id}">
        <input type="hidden" name="redirect_uri" value="${redirect_uri}">
        <input type="hidden" name="state" value="${state}">
        
        <div class="form-group">
          <label for="username">Username:</label>
          <input type="text" id="username" name="username" required>
        </div>
        
        <div class="form-group">
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" required>
        </div>
        
        <button type="submit">Login & Authorize</button>
      </form>
    </body>
    </html>
  `;

  sendHtmlResponse(res, loginForm);
}

// OAuth認証処理
function handleAuthorizationPost(req, res) {
  let body = '';
  req.on('data', chunk => body += chunk.toString());
  req.on('end', () => {
    const params = querystring.parse(body);
    const { username, password, client_id, redirect_uri, state } = params;

    const user = DUMMY_USERS[username];
    if (!user || user.password !== password) {
      sendHtmlResponse(res, '<h1>❌ Login Failed</h1><p>Invalid credentials</p>', 401);
      return;
    }

    const authCode = generateRandomString(16);
    authorizationCodes.set(authCode, {
      userId: user.id,
      clientId: client_id,
      redirectUri: redirect_uri,
      expiresAt: Date.now() + (10 * 60 * 1000)
    });

    const redirectUrl = `${redirect_uri}?code=${authCode}&state=${state}`;
    res.writeHead(302, { 'Location': redirectUrl });
    res.end();
  });
}

// OAuth トークンエンドポイント
function handleTokenEndpoint(req, res) {
  let body = '';
  req.on('data', chunk => body += chunk.toString());
  req.on('end', () => {
    const params = querystring.parse(body);
    const { grant_type, code, client_id, client_secret } = params;

    if (grant_type !== 'authorization_code') {
      sendJsonResponse(res, { error: 'unsupported_grant_type' }, 400);
      return;
    }

    // 静的クライアント または 動的クライアントをチェック
    let isValidClient = false;
    if (client_id === DUMMY_OAUTH_CONFIG.clientId && client_secret === DUMMY_OAUTH_CONFIG.clientSecret) {
      isValidClient = true;
    } else if (globalDynamicClients.has(client_id)) {
      const dynamicClient = globalDynamicClients.get(client_id);
      if (dynamicClient.client_secret === client_secret) {
        isValidClient = true;
      }
    }

    if (!isValidClient) {
      sendJsonResponse(res, { error: 'invalid_client' }, 401);
      return;
    }

    const authData = authorizationCodes.get(code);
    if (!authData || Date.now() > authData.expiresAt) {
      sendJsonResponse(res, { error: 'invalid_grant' }, 400);
      return;
    }

    const accessToken = generateRandomString(32);
    accessTokens.set(accessToken, {
      userId: authData.userId,
      scope: 'read write',
      createdAt: Date.now(),
      expiresAt: Date.now() + (3600 * 1000)
    });

    authorizationCodes.delete(code);

    sendJsonResponse(res, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 3600,
      scope: 'read write'
    });
  });
}

// HTTPサーバー
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end();
    return;
  }

  // OAuth Discovery Metadata (MCP Inspector用)
  if (req.method === 'GET' && parsedUrl.pathname === '/.well-known/oauth-authorization-server') {
    sendJsonResponse(res, {
      issuer: `http://localhost:${PORT}`,
      authorization_endpoint: `http://localhost:${PORT}/oauth/authorize`,
      token_endpoint: `http://localhost:${PORT}/oauth/token`,
      userinfo_endpoint: `http://localhost:${PORT}/oauth/userinfo`,
      registration_endpoint: `http://localhost:${PORT}/oauth/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      scopes_supported: ['read', 'write'],
      code_challenge_methods_supported: ['S256'],
      subject_types_supported: ['public']
    });
    return;
  }

  // Dynamic Client Registration エンドポイント
  if (req.method === 'POST' && parsedUrl.pathname === '/oauth/register') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      try {
        const registration = JSON.parse(body);
        
        // 動的にクライアント情報を生成
        const clientId = 'dyn_' + generateRandomString(16);
        const clientSecret = 'secret_' + generateRandomString(32);
        
        // クライアント情報を保存（本番では永続化が必要）
        const clientInfo = {
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uris: registration.redirect_uris || [DUMMY_OAUTH_CONFIG.redirectUri],
          client_name: registration.client_name || 'Dynamic MCP Client',
          grant_types: registration.grant_types || ['authorization_code'],
          response_types: registration.response_types || ['code'],
          scope: registration.scope || 'read write',
          created_at: Date.now()
        };
        
        // 動的クライアントを保存（簡易実装）
        globalDynamicClients.set(clientId, clientInfo);
        
        console.log(`📝 Dynamic client registered: ${clientId}`);
        
        sendJsonResponse(res, {
          client_id: clientId,
          client_secret: clientSecret,
          client_name: clientInfo.client_name,
          redirect_uris: clientInfo.redirect_uris,
          grant_types: clientInfo.grant_types,
          response_types: clientInfo.response_types,
          scope: clientInfo.scope,
          client_id_issued_at: Math.floor(Date.now() / 1000),
          client_secret_expires_at: 0  // 無期限
        }, 201);
        
      } catch (error) {
        console.error('Client registration error:', error);
        sendJsonResponse(res, {
          error: 'invalid_request',
          error_description: 'Invalid registration request'
        }, 400);
      }
    });
    return;
  }

  // OAuth ユーザー情報エンドポイント
  if (req.method === 'GET' && parsedUrl.pathname === '/oauth/userinfo') {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      sendJsonResponse(res, { error: 'invalid_token' }, 401);
      return;
    }

    const token = authHeader.substring(7);
    const user = getUserFromToken(token);
    
    if (!user) {
      sendJsonResponse(res, { error: 'invalid_token' }, 401);
      return;
    }

    sendJsonResponse(res, {
      sub: user.id,
      name: user.name,
      email: user.email,
      preferred_username: user.username,
      email_verified: true
    });
    return;
  }

  // OAuth エンドポイント
  if (req.method === 'GET' && parsedUrl.pathname === '/oauth/authorize') {
    handleAuthorizationEndpoint(req, res, parsedUrl);
    return;
  }

  if (req.method === 'POST' && parsedUrl.pathname === '/oauth/authorize') {
    handleAuthorizationPost(req, res);
    return;
  }

  if (req.method === 'POST' && parsedUrl.pathname === '/oauth/token') {
    handleTokenEndpoint(req, res);
    return;
  }

  // OAuth コールバック
  if (req.method === 'GET' && parsedUrl.pathname === '/oauth/callback') {
    const { code, state } = parsedUrl.query;
    sendHtmlResponse(res, `
      <html>
        <head><title>OAuth Success</title></head>
        <body>
          <h1>✅ Authentication Successful</h1>
          <p><strong>Authorization Code:</strong> ${code}</p>
          <p><strong>State:</strong> ${state}</p>
          <p>Authentication completed successfully! You can close this window.</p>
          <script>
            // MCP Inspector向けの自動クローズ
            setTimeout(() => {
              if (window.opener) {
                window.close();
              }
            }, 2000);
          </script>
        </body>
      </html>
    `);
    return;
  }

  // サーバー情報
  if (req.method === 'GET' && parsedUrl.pathname === '/') {
    sendJsonResponse(res, {
      name: 'HTTP MCP OAuth Server',
      version: '1.0.0',
      description: 'HTTP-based MCP Server with OAuth for Inspector',
      endpoints: {
        mcp: '/mcp',
        oauth_authorize: '/oauth/authorize',
        oauth_token: '/oauth/token',
        oauth_callback: '/oauth/callback',
        oauth_metadata: '/.well-known/oauth-authorization-server',
        oauth_userinfo: '/oauth/userinfo'
      },
      testUsers: Object.keys(DUMMY_USERS),
      inspector_config: {
        url: `http://localhost:${PORT}/mcp`,
        transport: 'http'
      }
    });
    return;
  }

  // MCPエンドポイント
  if (req.method === 'POST' && parsedUrl.pathname === '/mcp') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      try {
        const message = JSON.parse(body);
        
        // Authorization ヘッダーからトークン取得
        let authToken = null;
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
          authToken = authHeader.substring(7);
        }

        const response = handleMCPMessage(message, authToken);
        
        if (response) {
          sendJsonResponse(res, response);
        } else {
          res.writeHead(204);
          res.end();
        }
      } catch (error) {
        console.error('MCP Error:', error);
        sendJsonResponse(res, {
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Parse error' }
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
  console.log(`🚀 HTTP MCP OAuth Server running on http://localhost:${PORT}`);
  console.log(`📋 Server info: http://localhost:${PORT}/`);
  console.log(`🔗 MCP endpoint: http://localhost:${PORT}/mcp`);
  console.log(`🔐 OAuth authorize: http://localhost:${PORT}/oauth/authorize`);
  console.log(`📜 OAuth metadata: http://localhost:${PORT}/.well-known/oauth-authorization-server`);
  console.log('');
  console.log('📝 Test Users:');
  Object.entries(DUMMY_USERS).forEach(([username, user]) => {
    console.log(`   👤 ${username} / ${user.password} (${user.name})`);
  });
  console.log('');
  console.log('🔧 MCP Inspector Configuration:');
  console.log(`   Add to config.json:`);
  console.log(`   {`);
  console.log(`     "mcpServers": {`);
  console.log(`       "oauth-server": {`);
  console.log(`         "url": "http://localhost:${PORT}/mcp"`);
  console.log(`       }`);
  console.log(`     }`);
  console.log(`   }`);
  console.log('');
  console.log('🧪 Quick Test Steps:');
  console.log('   1. Start MCP Inspector with above config');
  console.log('   2. Go to Tools tab');
  console.log('   3. Use "quick_login" tool with inspector/inspector123');
  console.log('   4. Or try "Quick OAuth Flow" in Auth tab');
  console.log('   5. Check new authenticated tools appear');
  console.log('');
  console.log('💡 Pro tip: Use "quick_login" tool for fastest testing!');
});

process.on('SIGINT', () => {
  console.log('\n👋 Shutting down server...');
  server.close(() => process.exit(0));
});