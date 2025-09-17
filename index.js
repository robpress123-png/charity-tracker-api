/**
 * Charity Tracker - Cloudflare Workers API
 * Main entry point for all API routes
 * Version: v2.1.3
 * Build: 2025.01.17-03
 */

const VERSION = 'v2.1.3';
const BUILD = '2025.01.17-03';

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Max-Age': '86400',
};

// Handle CORS preflight requests
function handleCORS(request) {
  return new Response(null, {
    status: 200,
    headers: corsHeaders
  });
}

// Response helpers
function successResponse(data, message = 'Success', status = 200) {
  return new Response(JSON.stringify({
    success: true,
    message,
    data,
    timestamp: new Date().toISOString()
  }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders
    }
  });
}

function errorResponse(message, status = 400) {
  return new Response(JSON.stringify({
    success: false,
    message,
    errors: null,
    timestamp: new Date().toISOString()
  }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders
    }
  });
}

// Auth helpers
function getSessionFromRequest(request) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
}

async function validateSession(sessionId, env) {
  if (!sessionId) return null;

  try {
    const session = await env.DB.prepare(`
      SELECT s.id, s.user_id, s.expires_at, u.email, u.is_admin
      FROM user_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.id = ? AND s.expires_at > datetime('now')
    `).bind(sessionId).first();

    return session;
  } catch (error) {
    console.error('Session validation error:', error);
    return null;
  }
}

// Main worker
export default {
  async fetch(request, env, ctx) {
    try {
      // Handle CORS preflight requests
      if (request.method === 'OPTIONS') {
        return handleCORS(request);
      }

      const url = new URL(request.url);
      const pathname = url.pathname;

      // Version endpoint
      if (pathname === '/version') {
        console.log('✅ NEW BACKEND DEPLOYED - Version endpoint hit');
        return new Response(JSON.stringify({
          version: VERSION,
          build: BUILD,
          service: 'Charity Tracker API',
          deployment_status: 'GITHUB_DEPLOYMENT_SUCCESS',
          timestamp: new Date().toISOString()
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders
          }
        });
      }

      // Health check endpoint
      if (pathname === '/health') {
        return successResponse({
          status: 'ok',
          version: VERSION,
          build: BUILD,
          service: 'Charity Tracker API'
        });
      }

      // Route API requests
      if (pathname.startsWith('/api/')) {
        const apiPath = pathname.replace('/api', '');

        // User charities endpoints
        if (apiPath.startsWith('/user-charities')) {
          return await handleUserCharities(request, env, apiPath);
        }

        // Charities endpoints
        if (apiPath.startsWith('/charities')) {
          return await handleCharities(request, env, apiPath);
        }

        // Auth endpoints
        if (apiPath.startsWith('/auth')) {
          return await handleAuth(request, env, apiPath);
        }

        // Unknown API route
        return errorResponse('Not Found', 404);
      }

      // Default response
      return new Response('🚀 NEW BACKEND v2.1.3 DEPLOYED VIA GITHUB - Use /api/* endpoints', {
        status: 200,
        headers: corsHeaders
      });

    } catch (error) {
      console.error('Unhandled error:', error);
      return errorResponse('Internal Server Error', 500);
    }
  }
};

// User Charities Handler
async function handleUserCharities(request, env, path) {
  const method = request.method;

  console.log(`🔍 User Charities Route: ${method} ${path}`);

  switch (true) {
    case path === '/user-charities' && method === 'GET':
      return handleGetUserCharities(request, env);

    case path === '/user-charities' && method === 'POST':
      return handleCreateUserCharity(request, env);

    case path === '/user-charities/submit-for-approval' && method === 'POST':
      return handleSubmitForApproval(request, env);

    default:
      return errorResponse('Not Found', 404);
  }
}

async function handleCreateUserCharity(request, env) {
  try {
    console.log('🔧 Starting handleCreateUserCharity');

    // Require authentication
    const sessionId = getSessionFromRequest(request);
    console.log('🔑 Session ID found:', sessionId ? 'Yes' : 'No');

    const session = await validateSession(sessionId, env);
    console.log('👤 Session validation result:', session ? `User: ${session.user_id}` : 'Failed');

    if (!session) {
      console.log('❌ Authentication failed');
      return errorResponse('Authentication required', 401);
    }

    const body = await request.json();
    console.log('📥 Received data:', body);
    const { name, ein, address, city, state, zip } = body;

    // Validation
    if (!name || name.trim().length < 2) {
      return errorResponse('Charity name is required (minimum 2 characters)', 400);
    }

    // Create user charity
    const charityId = crypto.randomUUID();
    console.log('💾 Creating charity with ID:', charityId);

    const insertResult = await env.DB.prepare(`
      INSERT INTO user_charities (id, user_id, name, ein, address, city, state, zip)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      charityId,
      session.user_id,
      name.trim(),
      ein || null,
      address || null,
      city || null,
      state || null,
      zip || null
    ).run();

    console.log('💾 Insert result:', insertResult);

    // Return created charity
    const createdCharity = await env.DB.prepare(`
      SELECT id, name, ein, address, city, state, zip, created_at
      FROM user_charities WHERE id = ?
    `).bind(charityId).first();

    return successResponse(createdCharity, 'Personal charity added successfully', 201);

  } catch (error) {
    console.error('Create user charity error:', error);
    return errorResponse('Failed to create personal charity', 500);
  }
}

async function handleGetUserCharities(request, env) {
  try {
    const sessionId = getSessionFromRequest(request);
    const session = await validateSession(sessionId, env);

    if (!session) {
      return errorResponse('Authentication required', 401);
    }

    const userCharities = await env.DB.prepare(`
      SELECT id, name, ein, address, city, state, zip, is_submitted_for_approval, created_at
      FROM user_charities
      WHERE user_id = ?
      ORDER BY created_at DESC
    `).bind(session.user_id).all();

    return successResponse({
      charities: userCharities.results || []
    });

  } catch (error) {
    console.error('Get user charities error:', error);
    return errorResponse('Failed to retrieve personal charities', 500);
  }
}

async function handleSubmitForApproval(request, env) {
  try {
    const sessionId = getSessionFromRequest(request);
    const session = await validateSession(sessionId, env);

    if (!session) {
      return errorResponse('Authentication required', 401);
    }

    const body = await request.json();
    const { charityId } = body;

    if (!charityId) {
      return errorResponse('Charity ID is required', 400);
    }

    // Update the charity to mark as submitted for approval
    await env.DB.prepare(`
      UPDATE user_charities
      SET is_submitted_for_approval = TRUE
      WHERE id = ? AND user_id = ?
    `).bind(charityId, session.user_id).run();

    return successResponse(null, 'Charity submitted for approval successfully');

  } catch (error) {
    console.error('Submit for approval error:', error);
    return errorResponse('Failed to submit charity for approval', 500);
  }
}

// Charities Handler (simplified)
async function handleCharities(request, env, path) {
  if (path === '/charities' && request.method === 'GET') {
    try {
      const url = new URL(request.url);
      const verified = url.searchParams.get('verified');

      let whereClause = '';
      const params = [];

      if (verified !== null) {
        whereClause = 'WHERE is_verified = ?';
        params.push(verified === 'true');
      }

      const charities = await env.DB.prepare(`
        SELECT id, name, ein, is_verified, verification_date
        FROM charities
        ${whereClause}
        ORDER BY is_verified DESC, name ASC
        LIMIT 50
      `).bind(...params).all();

      return successResponse({
        charities: charities.results || [],
        // Backend version info for frontend display
        backend_version: {
          version: VERSION,
          build: BUILD,
          service: 'Charity Tracker API'
        }
      });

    } catch (error) {
      console.error('Get charities error:', error);
      return errorResponse('Failed to retrieve charities', 500);
    }
  }

  return errorResponse('Not Found', 404);
}

// Auth Handler (simplified)
async function handleAuth(request, env, path) {
  return errorResponse('Auth endpoints not implemented in this version', 501);
}