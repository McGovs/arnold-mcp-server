import express from 'express';
import cors from 'cors';
import { BetaAnalyticsDataClient } from '@google-analytics/data';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';
import pg from 'pg';

dotenv.config();

const { Pool } = pg;

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

// Handle pool errors
pool.on('error', (err) => {
  console.error('Unexpected database pool error:', err);
});

// OAuth2 client for token validation and refresh
const oauth2Client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET
);

// Initialize database tables
async function initDatabaseTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS arnold_users (
        id SERIAL PRIMARY KEY,
        slack_user_id VARCHAR(255) UNIQUE NOT NULL,
        google_access_token TEXT NOT NULL,
        google_refresh_token TEXT NOT NULL,
        token_expires_at BIGINT NOT NULL,
        ga_property_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_slack_user_id 
      ON arnold_users(slack_user_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        slack_user_id VARCHAR(255),
        action VARCHAR(100),
        property_id VARCHAR(255),
        ip_address VARCHAR(45),
        user_agent TEXT,
        success BOOLEAN,
        error_message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_audit_slack_user 
      ON audit_logs(slack_user_id, created_at DESC)
    `);
    
    console.log('✅ Database tables initialized');
  } catch (error) {
    console.error('Database init error:', error);
  }
}

// API Key middleware for security
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  
  if (!apiKey) {
    return res.status(401).json({ 
      error: 'API key required',
      message: 'Please provide X-API-Key header'
    });
  }
  
  if (apiKey !== process.env.API_KEY) {
    return res.status(403).json({ 
      error: 'Invalid API key',
      message: 'The provided API key is not valid'
    });
  }
  
  next();
};

// Validate and refresh OAuth token if needed
async function getValidAccessToken(userAccessToken, refreshToken = null) {
  try {
    oauth2Client.setCredentials({
      access_token: userAccessToken,
      refresh_token: refreshToken
    });

    try {
      const tokenInfo = await oauth2Client.getTokenInfo(userAccessToken);
      console.log('Token is valid, expires at:', new Date(tokenInfo.expiry_date));
      return userAccessToken;
    } catch (error) {
      if (refreshToken) {
        console.log('Token expired, attempting refresh...');
        const { credentials } = await oauth2Client.refreshAccessToken();
        console.log('Token refreshed successfully');
        return credentials.access_token;
      }
      throw new Error('Token expired and no refresh token provided');
    }
  } catch (error) {
    console.error('Token validation/refresh error:', error);
    throw error;
  }
}

// Audit logging function
async function logAuditEvent(slackUserId, action, propertyId, req, success, errorMessage = null) {
  try {
    await pool.query(`
      INSERT INTO audit_logs 
        (slack_user_id, action, property_id, ip_address, user_agent, success, error_message)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
      slackUserId,
      action,
      propertyId,
      req.ip || req.headers['x-forwarded-for'] || 'unknown',
      req.headers['user-agent'] || 'unknown',
      success,
      errorMessage
    ]);
  } catch (error) {
    console.error('Failed to log audit event:', error);
  }
}

// Validate property ID format
function validatePropertyId(propertyId) {
  const propertyIdRegex = /^properties\/\d+$/;
  return propertyIdRegex.test(propertyId);
}

// Request validation middleware
const validateAnalyticsRequest = (req, res, next) => {
  const { tool, args, userAccessToken } = req.body;
  
  if (!tool || typeof tool !== 'string') {
    return res.status(400).json({
      error: 'Invalid request',
      message: 'tool field is required and must be a string'
    });
  }
  
  if (!args || typeof args !== 'object') {
    return res.status(400).json({
      error: 'Invalid request',
      message: 'args field is required and must be an object'
    });
  }
  
  if (!args.property || !validatePropertyId(args.property)) {
    return res.status(400).json({
      error: 'Invalid property ID',
      message: 'property must be in format: properties/123456789'
    });
  }
  
  if (!userAccessToken || typeof userAccessToken !== 'string') {
    return res.status(400).json({
      error: 'Invalid request',
      message: 'userAccessToken is required'
    });
  }
  
  if (args.dateRanges && Array.isArray(args.dateRanges)) {
    for (const range of args.dateRanges) {
      if (!range.startDate || !range.endDate) {
        return res.status(400).json({
          error: 'Invalid date range',
          message: 'Each dateRange must have startDate and endDate'
        });
      }
    }
  }
  
  next();
};

// Health check endpoint (no auth required)
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// Main MCP endpoint for Google Analytics queries
app.post('/mcp/analytics', authenticateApiKey, validateAnalyticsRequest, async (req, res) => {
  const startTime = Date.now();
  
  try {
    console.log('Received request:', JSON.stringify(req.body, null, 2));

    const { tool, args, userAccessToken, refreshToken } = req.body;

    if (tool !== 'ga.runReport') {
      return res.status(400).json({
        error: 'Invalid tool specified',
        message: 'Expected tool: "ga.runReport"'
      });
    }

    console.log('Validating user OAuth token...');
    
    const validAccessToken = await getValidAccessToken(userAccessToken, refreshToken);
    
    console.log('Using user OAuth token for client:', args.property);

    // Initialize Google Analytics client with user's OAuth token
    const analyticsDataClient = new BetaAnalyticsDataClient({
      authClient: oauth2Client
    });

    const gaRequest = {
      property: args.property,
      dateRanges: args.dateRanges || [{ startDate: '7daysAgo', endDate: 'today' }],
      dimensions: args.dimensions || [],
      metrics: args.metrics || [],
      limit: args.limit || 10,
      offset: args.offset || 0,
      keepEmptyRows: args.keepEmptyRows !== undefined ? args.keepEmptyRows : false,
      metricAggregations: args.metricAggregations || []
    };

    console.log('Sending request to Google Analytics...');

    const [response] = await analyticsDataClient.runReport(gaRequest);

    console.log('Received response from Google Analytics');
    console.log(`Returned ${response.rows?.length || 0} rows`);

    await logAuditEvent(
      'unknown',
      'analytics_query',
      args.property,
      req,
      true
    );

    const formattedResponse = {
      success: true,
      data: {
        dimensionHeaders: response.dimensionHeaders?.map(h => ({
          name: h.name
        })),
        metricHeaders: response.metricHeaders?.map(h => ({
          name: h.name,
          type: h.type
        })),
        rows: response.rows?.map(row => ({
          dimensionValues: row.dimensionValues?.map(v => v.value),
          metricValues: row.metricValues?.map(v => v.value)
        })),
        rowCount: response.rowCount,
        metadata: {
          currencyCode: response.metadata?.currencyCode,
          timeZone: response.metadata?.timeZone
        }
      },
      timestamp: new Date().toISOString(),
      authMethod: 'user_oauth',
      property: args.property
    };

    console.log(`Query completed in ${Date.now() - startTime}ms`);

    res.json(formattedResponse);

  } catch (error) {
    console.error('Error processing request:', error);
    
    await logAuditEvent(
      'unknown',
      'analytics_query',
      req.body.args?.property,
      req,
      false,
      error.message
    );

    let errorMessage = error.message;
    let errorCode = 500;

    if (error.message.includes('PERMISSION_DENIED') || error.message.includes('403')) {
      errorMessage = 'User does not have access to this Google Analytics property';
      errorCode = 403;
    } else if (error.message.includes('NOT_FOUND') || error.message.includes('404')) {
      errorMessage = 'Google Analytics property not found';
      errorCode = 404;
    } else if (error.message.includes('invalid_grant') || error.message.includes('Token expired')) {
      errorMessage = 'OAuth token expired or invalid. User needs to re-authenticate.';
      errorCode = 401;
    }
    
    res.status(errorCode).json({
      success: false,
      error: errorMessage,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      timestamp: new Date().toISOString()
    });
  }
});

// Alternative simpler endpoint (also requires user token)
app.post('/analytics/query', authenticateApiKey, async (req, res) => {
  try {
    const { propertyId, dateRanges, dimensions, metrics, limit, offset, userAccessToken, refreshToken } = req.body;

    if (!propertyId) {
      return res.status(400).json({
        error: 'Missing required parameter: propertyId'
      });
    }

    if (!userAccessToken) {
      return res.status(400).json({
        error: 'User access token required',
        message: 'userAccessToken is required to access client Google Analytics data'
      });
    }

    const validAccessToken = await getValidAccessToken(userAccessToken, refreshToken);

    const analyticsDataClient = new BetaAnalyticsDataClient({
      authClient: oauth2Client
    });

    const gaRequest = {
      property: `properties/${propertyId}`,
      dateRanges: dateRanges || [{ startDate: '7daysAgo', endDate: 'today' }],
      dimensions: dimensions || [],
      metrics: metrics || [],
      limit: limit || 10,
      offset: offset || 0
    };

    const [response] = await analyticsDataClient.runReport(gaRequest);

    res.json({
      success: true,
      data: response,
      timestamp: new Date().toISOString(),
      authMethod: 'user_oauth'
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Store user tokens after OAuth
app.post('/users/tokens', authenticateApiKey, async (req, res) => {
  try {
    const { 
      slackUserId, 
      accessToken, 
      refreshToken, 
      expiresIn, 
      propertyId 
    } = req.body;

    if (!slackUserId || !accessToken || !refreshToken) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['slackUserId', 'accessToken', 'refreshToken']
      });
    }

    const expiresAt = Date.now() + (expiresIn * 1000);

    const query = `
      INSERT INTO arnold_users 
        (slack_user_id, google_access_token, google_refresh_token, token_expires_at, ga_property_id, updated_at)
      VALUES 
        ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
      ON CONFLICT (slack_user_id) 
      DO UPDATE SET
        google_access_token = $2,
        google_refresh_token = $3,
        token_expires_at = $4,
        ga_property_id = $5,
        updated_at = CURRENT_TIMESTAMP
      RETURNING id, slack_user_id, token_expires_at
    `;

    const result = await pool.query(query, [
      slackUserId,
      accessToken,
      refreshToken,
      expiresAt,
      propertyId
    ]);

    res.json({
      success: true,
      message: 'User tokens stored successfully',
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Error storing user tokens:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get user tokens
app.get('/users/:slackUserId/tokens', authenticateApiKey, async (req, res) => {
  try {
    const { slackUserId } = req.params;

    const query = `
      SELECT 
        slack_user_id,
        google_access_token,
        google_refresh_token,
        token_expires_at,
        ga_property_id
      FROM arnold_users
      WHERE slack_user_id = $1
    `;

    const result = await pool.query(query, [slackUserId]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'User not found',
        message: 'This user has not connected their Google Analytics account'
      });
    }

    const user = result.rows[0];

    res.json({
      success: true,
      slackUserId: user.slack_user_id,
      accessToken: user.google_access_token,
      refreshToken: user.google_refresh_token,
      expiresAt: user.token_expires_at,
      isExpired: Date.now() > user.token_expires_at,
      propertyId: user.ga_property_id
    });

  } catch (error) {
    console.error('Error fetching user tokens:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get user's GA4 properties
app.get('/users/:slackUserId/properties', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  
  if (apiKey !== process.env.MCP_API_KEY) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  
  const { slackUserId } = req.params;
  
  try {
    // Get user's tokens from database
    const result = await pool.query(
      'SELECT google_access_token, google_refresh_token FROM arnold_users WHERE slack_user_id = $1',
      [slackUserId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    
    const { google_access_token, google_refresh_token } = result.rows[0];
    
    // Fetch properties from Google Analytics Admin API
    const response = await axios.get(
      'https://analyticsadmin.googleapis.com/v1beta/accountSummaries',
      {
        headers: {
          'Authorization': `Bearer ${access_token}`
        }
      }
    );
    
    // Extract properties
    const properties = [];
    
    if (response.data.accountSummaries) {
      for (const account of response.data.accountSummaries) {
        if (account.propertySummaries) {
          for (const prop of account.propertySummaries) {
            properties.push({
              id: prop.property,
              name: prop.displayName,
              account: account.displayName
            });
          }
        }
      }
    }
    
    res.json({
      success: true,
      properties: properties
    });
    
  } catch (error) {
    console.error('Error fetching properties:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Update user's property ID
app.patch('/users/:slackUserId/property', authenticateApiKey, async (req, res) => {
  try {
    const { slackUserId } = req.params;
    const { propertyId } = req.body;

    if (!propertyId) {
      return res.status(400).json({
        error: 'Property ID required'
      });
    }

    const query = `
      UPDATE arnold_users
      SET ga_property_id = $1, updated_at = CURRENT_TIMESTAMP
      WHERE slack_user_id = $2
      RETURNING slack_user_id, ga_property_id
    `;

    const result = await pool.query(query, [propertyId, slackUserId]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Error updating property ID:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Delete user tokens (disconnect)
app.delete('/users/:slackUserId/tokens', authenticateApiKey, async (req, res) => {
  try {
    const { slackUserId } = req.params;

    const query = `
      DELETE FROM arnold_users
      WHERE slack_user_id = $1
      RETURNING slack_user_id
    `;

    const result = await pool.query(query, [slackUserId]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    res.json({
      success: true,
      message: 'User tokens deleted successfully'
    });

  } catch (error) {
    console.error('Error deleting user tokens:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Token refresh endpoint
app.post('/oauth/refresh', authenticateApiKey, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        error: 'Refresh token required'
      });
    }

    oauth2Client.setCredentials({
      refresh_token: refreshToken
    });

    const { credentials } = await oauth2Client.refreshAccessToken();

    res.json({
      success: true,
      accessToken: credentials.access_token,
      expiresIn: credentials.expiry_date ? Math.floor((credentials.expiry_date - Date.now()) / 1000) : 3600,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to refresh token',
      message: error.message
    });
  }
});

// List all connected users (admin only)
app.get('/users', authenticateApiKey, async (req, res) => {
  try {
    const query = `
      SELECT 
        slack_user_id,
        ga_property_id,
        token_expires_at,
        created_at,
        updated_at
      FROM arnold_users
      ORDER BY created_at DESC
    `;

    const result = await pool.query(query);

    res.json({
      success: true,
      count: result.rows.length,
      users: result.rows.map(user => ({
        slackUserId: user.slack_user_id,
        propertyId: user.ga_property_id,
        isTokenExpired: Date.now() > user.token_expires_at,
        connectedAt: user.created_at,
        lastUpdated: user.updated_at
      }))
    });

  } catch (error) {
    console.error('Error listing users:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// API Documentation endpoint
app.get('/docs', (req, res) => {
  res.json({
    name: 'Arnold MCP Server',
    version: '2.0.0',
    description: 'Google Analytics Data API via Model Context Protocol',
    endpoints: {
      health: {
        method: 'GET',
        path: '/health',
        description: 'Health check endpoint',
        auth: 'None'
      },
      analytics: {
        method: 'POST',
        path: '/mcp/analytics',
        description: 'Run Google Analytics query',
        auth: 'X-API-Key header',
        body: {
          tool: 'string (required) - Must be "ga.runReport"',
          args: {
            property: 'string (required) - Format: properties/123456789',
            dateRanges: 'array - [{ startDate, endDate }]',
            dimensions: 'array - [{ name }]',
            metrics: 'array - [{ name }]',
            limit: 'number - Max rows to return',
            offset: 'number - Pagination offset'
          },
          userAccessToken: 'string (required) - User\'s OAuth access token',
          refreshToken: 'string (optional) - For automatic token refresh'
        }
      },
      storeTokens: {
        method: 'POST',
        path: '/users/tokens',
        description: 'Store user OAuth tokens',
        auth: 'X-API-Key header'
      },
      getTokens: {
        method: 'GET',
        path: '/users/:slackUserId/tokens',
        description: 'Retrieve user tokens',
        auth: 'X-API-Key header'
      },
      refreshToken: {
        method: 'POST',
        path: '/oauth/refresh',
        description: 'Refresh expired access token',
        auth: 'X-API-Key header'
      }
    },
    support: 'https://github.com/yourusername/arnold-mcp-server'
  });
});

// Serve docs at root
app.get('/', (req, res) => {
  res.redirect('/docs');
});

// Start server
async function startServer() {
  await initDatabaseTables();
  
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Arnold MCP Server v2.0 running on port ${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/health`);
    console.log(`🔍 MCP endpoint: http://localhost:${PORT}/mcp/analytics`);
    console.log(`📈 Direct endpoint: http://localhost:${PORT}/analytics/query`);
    console.log(`🔄 Token refresh: http://localhost:${PORT}/oauth/refresh`);
    console.log(`⚠️  User OAuth token REQUIRED for all analytics queries`);
  });
}

startServer();
