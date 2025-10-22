import express from 'express';
import cors from 'cors';
import { BetaAnalyticsDataClient } from '@google-analytics/data';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 3000;

// OAuth2 client for token validation and refresh
const oauth2Client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET
);

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

// Health check endpoint (no auth required)
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    version: '2.0.0'
  });
});

// Validate and refresh OAuth token if needed
async function getValidAccessToken(userAccessToken, refreshToken = null) {
  try {
    // Set the credentials
    oauth2Client.setCredentials({
      access_token: userAccessToken,
      refresh_token: refreshToken
    });

    // Try to get token info to validate it
    try {
      const tokenInfo = await oauth2Client.getTokenInfo(userAccessToken);
      console.log('Token is valid, expires at:', new Date(tokenInfo.expiry_date));
      return userAccessToken;
    } catch (error) {
      // Token might be expired, try to refresh if we have refresh token
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

// Main MCP endpoint for Google Analytics queries
app.post('/mcp/analytics', authenticateApiKey, async (req, res) => {
  try {
    console.log('Received request:', JSON.stringify(req.body, null, 2));

    const { tool, args, userAccessToken, refreshToken } = req.body;

    // Validate tool
    if (!tool || tool !== 'ga.runReport') {
      return res.status(400).json({
        error: 'Invalid tool specified',
        message: 'Expected tool: "ga.runReport"'
      });
    }

    // Validate required parameters
    if (!args || !args.property) {
      return res.status(400).json({
        error: 'Missing required parameters',
        message: 'Required: args.property'
      });
    }

    // CRITICAL: User access token is REQUIRED for client data
    if (!userAccessToken) {
      return res.status(400).json({
        error: 'User access token required',
        message: 'userAccessToken is required to access client Google Analytics data'
      });
    }

    console.log('Validating user OAuth token...');
    
    // Validate and potentially refresh the token
    const validAccessToken = await getValidAccessToken(userAccessToken, refreshToken);
    
    console.log('Using user OAuth token for client:', args.property);

    // Initialize Google Analytics client with user's OAuth token
    const analyticsDataClient = new BetaAnalyticsDataClient({
      authClient: oauth2Client
    });

    // Build the request for Google Analytics
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
    console.log('Request details:', JSON.stringify(gaRequest, null, 2));

    // Call Google Analytics Data API using client's credentials
    const [response] = await analyticsDataClient.runReport(gaRequest);

    console.log('Received response from Google Analytics');
    console.log(`Returned ${response.rows?.length || 0} rows`);

    // Format the response
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

    res.json(formattedResponse);

  } catch (error) {
    console.error('Error processing request:', error);
    
    // Provide detailed error messages
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

app.listen(PORT, () => {
  console.log(`🚀 Arnold MCP Server v2.0 running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔍 MCP endpoint: http://localhost:${PORT}/mcp/analytics`);
  console.log(`📈 Direct endpoint: http://localhost:${PORT}/analytics/query`);
  console.log(`🔄 Token refresh: http://localhost:${PORT}/oauth/refresh`);
  console.log(`⚠️  User OAuth token REQUIRED for all analytics queries`);
});
```

Click "Commit changes..." → "Commit changes"

---

**File 3: `.gitignore`**

Click "Add file" → "Create new file"
Name: `.gitignore`
```
node_modules/
.env
.DS_Store
*.log
.vscode/
credentials.json
token.json
```

Click "Commit changes..." → "Commit changes"

**✅ Code files created!**

---

## Phase 4: Deploy to Railway (15 minutes)

### Step 4.1: Connect GitHub to Railway

1. Go back to https://railway.app
2. Click "New Project"
3. Click "Deploy from GitHub repo"
4. If this is your first time: Click "Configure GitHub App"
   - Choose "Only select repositories"
   - Select `arnold-mcp-server`
   - Click "Install & Authorize"
5. You'll see your repository listed
6. Click on `arnold-mcp-server`
7. Click "Deploy Now"

### Step 4.2: Add Environment Variables

1. After deployment starts, click on your project
2. Click on the service (should say "arnold-mcp-server")
3. Click the "Variables" tab

**Add Variable 1: GOOGLE_CLIENT_ID**

1. Click "New Variable"
2. Variable name: `GOOGLE_CLIENT_ID`
3. Variable value: Paste your Client ID from Step 2.4
4. Click "Add"

**Add Variable 2: GOOGLE_CLIENT_SECRET**

1. Click "New Variable"
2. Variable name: `GOOGLE_CLIENT_SECRET`
3. Variable value: Paste your Client Secret from Step 2.4
4. Click "Add"

**Add Variable 3: API_KEY**

1. Click "New Variable"
2. Variable name: `API_KEY`
3. Variable value: Generate a random string (use https://www.uuidgenerator.net/)
   - Example: `a7f3c9e2-5b8d-4f1a-9c3e-7d2b8f4a6e1c`
4. Click "Add"

**Add Variable 4: NODE_ENV**

1. Click "New Variable"
2. Variable name: `NODE_ENV`
3. Variable value: `production`
4. Click "Add"

### Step 4.3: Get Your Public URL

1. Click the "Settings" tab
2. Scroll to "Networking" section
3. Click "Generate Domain"
4. Railway will create a public URL like: `arnold-mcp-server-production.up.railway.app`
5. **Copy this URL** - you'll need it!

### Step 4.4: Update OAuth Redirect URIs

1. Go back to Google Cloud Console
2. APIs & Services → Credentials
3. Click on your OAuth 2.0 Client ID
4. Under "Authorized redirect URIs", add:
   - `https://[YOUR-RAILWAY-URL]/oauth/callback`
5. Click "SAVE"

### Step 4.5: Test Your Deployment

1. Open a new browser tab
2. Go to: `https://[YOUR-RAILWAY-URL]/health`
3. You should see: `{"status":"healthy","version":"2.0.0",...}`

**🎉 Your server is live!**

---

## Phase 5: Slack App OAuth Flow (CRITICAL)

This is where you capture the user's OAuth token.

### Step 5.1: Configure Slack OAuth

In your Slack app configuration:

1. Go to https://api.slack.com/apps
2. Select your Arnold app
3. Go to "OAuth & Permissions"
4. Under "Redirect URLs", add your OAuth callback URL
5. Under "Scopes", make sure you have the permissions you need

### Step 5.2: Add Google OAuth to Your Slack App

When a user installs/opens your Slack app:

1. **User clicks "Connect Google Analytics"** button in Slack
2. **Slack app redirects to Google OAuth URL:**
```
https://accounts.google.com/o/oauth2/v2/auth?
  client_id=YOUR_CLIENT_ID
  &redirect_uri=https://your-slack-app-backend/oauth/callback
  &response_type=code
  &scope=https://www.googleapis.com/auth/analytics.readonly
  &access_type=offline
  &prompt=consent
  &state=USER_SLACK_ID
