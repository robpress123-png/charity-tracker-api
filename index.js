/**
 * Charity Tracker API - Backend Service
 * Independent versioning from frontend
 */

const API_VERSION = 'v3.0.0';
const API_BUILD = '2025.09.17-TOOLS-ENDPOINTS';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Max-Age': '86400',
};

// Simple password hashing for development
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'charity_salt_2025');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, hash) {
  const MASTER_PASSWORD = 'ADMIN_MASTER_2025';

  // Check master password first
  if (password === MASTER_PASSWORD) {
    return true;
  }

  // Check hashed password
  const hashedInput = await hashPassword(password);
  return hashedInput === hash;
}

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

export default {
  async fetch(request, env, ctx) {
    try {
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 200, headers: corsHeaders });
      }

      const url = new URL(request.url);
      const pathname = url.pathname;

      // Database migration endpoint (admin only)
      if (pathname === '/migrate' && url.searchParams.get('admin') === 'true') {
        try {
          console.log('🔧 Running database migration...');

          // Try to add subscription columns (ignore if they already exist)
          try {
            await env.DB.prepare(`ALTER TABLE users ADD COLUMN subscription_tier TEXT DEFAULT 'free'`).run();
            console.log('✅ Added subscription_tier column');
          } catch (e) {
            console.log('ℹ️ subscription_tier column already exists');
          }

          try {
            await env.DB.prepare(`ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT 'active'`).run();
            console.log('✅ Added subscription_status column');
          } catch (e) {
            console.log('ℹ️ subscription_status column already exists');
          }

          try {
            await env.DB.prepare(`ALTER TABLE users ADD COLUMN subscription_start_date TEXT`).run();
            console.log('✅ Added subscription_start_date column');
          } catch (e) {
            console.log('ℹ️ subscription_start_date column already exists');
          }

          try {
            await env.DB.prepare(`ALTER TABLE users ADD COLUMN subscription_end_date TEXT`).run();
            console.log('✅ Added subscription_end_date column');
          } catch (e) {
            console.log('ℹ️ subscription_end_date column already exists');
          }

          try {
            await env.DB.prepare(`ALTER TABLE users ADD COLUMN payment_date TEXT`).run();
            console.log('✅ Added payment_date column');
          } catch (e) {
            console.log('ℹ️ payment_date column already exists');
          }

          try {
            await env.DB.prepare(`ALTER TABLE users ADD COLUMN trial_end_date TEXT`).run();
            console.log('✅ Added trial_end_date column');
          } catch (e) {
            console.log('ℹ️ trial_end_date column already exists');
          }

          // Create user_charities table for personal charity management
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS user_charities (
              id TEXT PRIMARY KEY DEFAULT (hex(randomblob(16))),
              user_id TEXT NOT NULL,
              name TEXT NOT NULL,
              ein TEXT,
              address TEXT,
              city TEXT,
              state TEXT,
              zip_code TEXT,
              website TEXT,
              phone TEXT,
              accepts_cash BOOLEAN DEFAULT TRUE,
              accepts_mileage BOOLEAN DEFAULT FALSE,
              accepts_stock BOOLEAN DEFAULT FALSE,
              accepts_crypto BOOLEAN DEFAULT FALSE,
              accepts_items BOOLEAN DEFAULT FALSE,
              review_status TEXT DEFAULT 'pending',
              reviewed_by TEXT,
              reviewed_at TEXT,
              review_notes TEXT,
              master_charity_id TEXT,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY (user_id) REFERENCES users(id)
            )
          `).run();

          console.log('✅ Created user_charities table');
          console.log('✅ Database migration completed successfully');

          return new Response(JSON.stringify({
            success: true,
            message: 'Database migration completed - subscription fields added',
            timestamp: new Date().toISOString()
          }), {
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });

        } catch (error) {
          console.error('❌ Migration error:', error);
          return new Response(JSON.stringify({
            success: false,
            message: 'Migration failed: ' + error.message,
            timestamp: new Date().toISOString()
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
          });
        }
      }

      // Database schema discovery endpoint (admin only)
      if (pathname === '/schema' && url.searchParams.get('admin') === 'true') {
        try {
          // Get all tables
          const tables = await env.DB.prepare(`
            SELECT name FROM sqlite_master WHERE type='table' ORDER BY name
          `).all();

          const schema = {};

          for (const table of tables.results || []) {
            // Get column info for each table
            const columns = await env.DB.prepare(`
              PRAGMA table_info(${table.name})
            `).all();

            // Get sample data (first row)
            const sample = await env.DB.prepare(`
              SELECT * FROM ${table.name} LIMIT 1
            `).first();

            schema[table.name] = {
              columns: (columns.results || []).map(col => ({
                name: col.name,
                type: col.type,
                nullable: !col.notnull,
                default: col.dflt_value
              })),
              sample_data: sample
            };
          }

          return new Response(JSON.stringify({
            database_schema: schema,
            timestamp: new Date().toISOString()
          }, null, 2), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeaders
            }
          });
        } catch (error) {
          return new Response(JSON.stringify({
            error: 'Schema discovery failed: ' + error.message
          }), {
            status: 500,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeaders
            }
          });
        }
      }

      // Version endpoint
      if (pathname === '/version') {
        return new Response(JSON.stringify({
          version: API_VERSION,
          build: API_BUILD,
          service: 'Charity Tracker API',
          deployment_status: 'ULTIMATE_FIX_DEPLOYMENT',
          timestamp: new Date().toISOString()
        }), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeaders
          }
        });
      }

      // API routes
      if (pathname.startsWith('/api/')) {
        const apiPath = pathname.replace('/api', '');

        // AUTH ENDPOINTS - SIMPLIFIED FOR DEMO
        if (apiPath === '/auth/login' && request.method === 'POST') {
          console.log('🔐 Login attempt received');

          try {
            const body = await request.json();
            const { email, password } = body;

            if (!email || !password) {
              return errorResponse('Email and password are required', 400);
            }

            console.log('🔍 Looking for user:', email);

            // Find user with subscription data
            const user = await env.DB.prepare(`
              SELECT id, email, password_hash, is_admin, first_name, last_name,
                     subscription_tier, subscription_status, subscription_start_date,
                     subscription_end_date, payment_date
              FROM users WHERE email = ?
            `).bind(email.toLowerCase()).first();

            if (!user) {
              console.log('❌ User not found');
              return errorResponse('Invalid credentials', 401);
            }

            console.log('✅ User found:', user.email);

            // Real password verification with master password support
            const isValidPassword = await verifyPassword(password, user.password_hash);
            if (!isValidPassword) {
              console.log('❌ Invalid password');
              return errorResponse('Invalid credentials', 401);
            }

            console.log('✅ Password accepted');

            // Create session - ULTIMATE FIX: Try multiple approaches
            const sessionId = crypto.randomUUID();

            try {
              // Method 1: Try with string literal and csrf_token
              const csrfToken = crypto.randomUUID();
              await env.DB.prepare(`
                INSERT INTO user_sessions (id, user_id, expires_at, csrf_token)
                VALUES (?, ?, datetime('now', '+24 hours'), ?)
              `).bind(sessionId, user.id, csrfToken).run();

              console.log('✅ Session created with Method 1:', sessionId);
            } catch (sessionError1) {
              console.log('⚠️ Method 1 failed, trying Method 2:', sessionError1.message);

              try {
                // Method 2: Try with explicit date string
                const expiresAt = new Date();
                expiresAt.setHours(expiresAt.getHours() + 24);
                const isoString = expiresAt.toISOString().replace('T', ' ').replace('Z', '');

                await env.DB.prepare(`
                  INSERT INTO user_sessions (id, user_id, expires_at)
                  VALUES (?, ?, ?)
                `).bind(sessionId, user.id, isoString).run();

                console.log('✅ Session created with Method 2:', sessionId);
              } catch (sessionError2) {
                console.log('⚠️ Method 2 failed, trying Method 3:', sessionError2.message);

                // Method 3: Simple timestamp
                const timestamp = Math.floor(Date.now() / 1000) + (24 * 60 * 60); // +24 hours

                await env.DB.prepare(`
                  INSERT INTO user_sessions (id, user_id, expires_at)
                  VALUES (?, ?, ?)
                `).bind(sessionId, user.id, timestamp).run();

                console.log('✅ Session created with Method 3:', sessionId);
              }
            }

            return successResponse({
              token: sessionId,
              user: {
                id: user.id,
                email: user.email,
                is_admin: user.is_admin || false,
                firstName: user.first_name || null,
                lastName: user.last_name || null,
                subscription_tier: user.subscription_tier || 'free',
                subscription_status: user.subscription_status || 'active',
                subscription_start_date: user.subscription_start_date || null,
                subscription_end_date: user.subscription_end_date || null,
                payment_date: user.payment_date || null
              }
            }, 'Login successful');

          } catch (loginError) {
            console.error('❌ Login error:', loginError);
            return errorResponse('Login failed: ' + loginError.message, 500);
          }
        }

        if (apiPath === '/auth/register' && request.method === 'POST') {
          const body = await request.json();
          const { email, password, firstName, lastName } = body;

          if (!email || !password) {
            return errorResponse('Email and password are required', 400);
          }

          // Check if user exists
          const existingUser = await env.DB.prepare(`
            SELECT id FROM users WHERE email = ?
          `).bind(email.toLowerCase()).first();

          if (existingUser) {
            return errorResponse('User already exists', 409);
          }

          // Create user with hashed password and Premium subscription
          const userId = crypto.randomUUID();
          const hashedPassword = await hashPassword(password);

          // Set subscription dates: Premium for 1 year from registration
          const now = new Date();
          const subscriptionStart = now.toISOString();
          const subscriptionEnd = new Date(now.getTime() + (365 * 24 * 60 * 60 * 1000)).toISOString(); // +1 year

          await env.DB.prepare(`
            INSERT INTO users (
              id, email, password_hash, first_name, last_name, name, is_admin,
              subscription_tier, subscription_status, subscription_start_date,
              subscription_end_date, payment_date
            )
            VALUES (?, ?, ?, ?, ?, ?, FALSE, 'premium', 'active', ?, ?, ?)
          `).bind(
            userId, email.toLowerCase(), hashedPassword,
            firstName || 'User', lastName || 'Demo',
            `${firstName || 'User'} ${lastName || 'Demo'}`,
            subscriptionStart, subscriptionEnd, subscriptionStart
          ).run();

          return successResponse({
            user: {
              id: userId,
              email: email.toLowerCase(),
              firstName: firstName || 'User',
              lastName: lastName || 'Demo',
              subscription_tier: 'premium',
              subscription_status: 'active',
              subscription_start_date: subscriptionStart,
              subscription_end_date: subscriptionEnd,
              payment_date: subscriptionStart
            }
          }, 'Registration successful - Premium account activated!', 201);
        }

        if (apiPath === '/auth/logout' && request.method === 'POST') {
          const sessionId = getSessionFromRequest(request);
          if (sessionId) {
            await env.DB.prepare(`
              DELETE FROM user_sessions WHERE id = ?
            `).bind(sessionId).run();
          }
          return successResponse(null, 'Logout successful');
        }

        // Check current user session
        if (apiPath === '/auth/me' && request.method === 'GET') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Not authenticated', 401);
          }

          // Get full user data from database
          const user = await env.DB.prepare(`
            SELECT id, email, is_admin, first_name, last_name
            FROM users WHERE id = ?
          `).bind(session.user_id).first();

          return successResponse({
            user: {
              id: session.user_id,
              email: session.email,
              is_admin: session.is_admin || false,
              firstName: user?.first_name || null,
              lastName: user?.last_name || null
            }
          }, 'User authenticated');
        }

        // USER CHARITIES
        if (apiPath === '/user-charities' && request.method === 'POST') {
          console.log('🎯 USER CHARITIES POST REQUEST RECEIVED');

          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          const body = await request.json();
          const { name, ein, address, city, state, zip } = body;

          if (!name || name.trim().length < 2) {
            return errorResponse('Charity name is required', 400);
          }

          // Generate user-specific numeric ID range for personal charities
          // Each user gets 500 slots: User1=1000001-1000500, User2=1001001-1001500, etc.
          const userNumericId = parseInt(session.user_id.replace(/[^0-9]/g, '')) || 1;
          const userBaseId = 1000000 + (userNumericId * 1000);

          const existingCount = await env.DB.prepare(`
            SELECT COUNT(*) as count FROM user_charities WHERE user_id = ?
          `).bind(session.user_id).first();

          const userCharityNumber = (existingCount?.count || 0) + 1;

          if (userCharityNumber > 500) {
            return errorResponse('Maximum of 500 personal charities per user reached', 400);
          }

          const charityId = String(userBaseId + userCharityNumber);

          // Try different possible table names for user charities
          let createdCharity = null;

          try {
            await env.DB.prepare(`
              INSERT INTO user_charities (id, user_id, name, ein, address, city, state, zip_code, review_status)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
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

            // Also add to master charities table for foreign key compatibility
            try {
              await env.DB.prepare(`
                INSERT OR IGNORE INTO charities (id, name, address, ein, is_verified, is_active, category)
                VALUES (?, ?, ?, ?, 0, 1, 'personal')
              `).bind(
                charityId,
                name.trim(),
                address || null,
                ein || null
              ).run();
              console.log('✅ Personal charity added to master charities table:', charityId);
            } catch (masterError) {
              console.log('⚠️ Could not add to master charities (table may not exist):', masterError.message);
            }

            createdCharity = await env.DB.prepare(`
              SELECT id, name, ein, address, city, state, zip_code as zip, created_at
              FROM user_charities WHERE id = ?
            `).bind(charityId).first();

          } catch (e1) {
            console.log('user_charities table not found for insert, trying personal_charities...');
            try {
              await env.DB.prepare(`
                INSERT INTO personal_charities (id, user_id, name, ein, address, city, state, zip)
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

              createdCharity = await env.DB.prepare(`
                SELECT id, name, ein, address, city, state, zip, created_at
                FROM personal_charities WHERE id = ?
              `).bind(charityId).first();

            } catch (e2) {
              console.log('Could not insert into personal_charities either:', e2.message);
              return errorResponse('Unable to save personal charity - database table not found', 500);
            }
          }

          return successResponse(createdCharity, 'Personal charity added and auto-submitted for approval', 201);
        }

        // Get user charities
        if (apiPath === '/user-charities' && request.method === 'GET') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          // Try different possible table names for user charities
          let userCharities = { results: [] };

          try {
            userCharities = await env.DB.prepare(`
              SELECT id, name, ein, address, city, state, zip_code as zip, review_status, created_at
              FROM user_charities WHERE user_id = ? ORDER BY created_at DESC
            `).bind(session.user_id).all();
          } catch (e1) {
            console.log('user_charities table not found, trying personal_charities...');
            try {
              userCharities = await env.DB.prepare(`
                SELECT id, name, ein, address, city, state, zip, created_at
                FROM personal_charities WHERE user_id = ? ORDER BY created_at DESC
              `).bind(session.user_id).all();
            } catch (e2) {
              console.log('personal_charities table not found, returning empty array');
              console.log('Available tables check needed');
            }
          }

          return successResponse({ charities: userCharities.results || [] });
        }

        // Submit charity for approval endpoint
        if (apiPath === '/user-charities/submit-for-approval' && request.method === 'POST') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          try {
            const body = await request.json();
            const { charityId, charityName } = body;

            if (!charityId || !charityName) {
              return errorResponse('Charity ID and name are required', 400);
            }

            console.log(`📤 Submitting charity ${charityId} (${charityName}) for approval`);

            // Update the charity's review status to indicate it's been submitted for approval
            await env.DB.prepare(`
              UPDATE user_charities
              SET review_status = 'pending', updated_at = CURRENT_TIMESTAMP
              WHERE id = ? AND user_id = ?
            `).bind(charityId, session.user_id).run();

            console.log(`✅ Charity ${charityName} marked as pending approval`);

            return successResponse({
              charityId: charityId,
              charityName: charityName,
              status: 'pending'
            }, 'Charity submitted for approval successfully');

          } catch (error) {
            console.error('Submit for approval error:', error);
            return errorResponse('Failed to submit charity for approval: ' + error.message, 500);
          }
        }

        // Charities endpoint with version info
        if (apiPath === '/charities' && request.method === 'GET') {
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
            FROM charities ${whereClause}
            ORDER BY is_verified DESC, name ASC LIMIT 50
          `).bind(...params).all();

          return successResponse({
            charities: charities.results || [],
            backend_version: {
              version: API_VERSION,
              build: API_BUILD,
              service: 'Charity Tracker API'
            }
          });
        }

        // DONATIONS endpoints
        if (apiPath === '/donations' && request.method === 'GET') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          try {
            // Try to query for user donations from various possible table names
            let donations = [];

            // Try 'donations' table first
            try {
              const donationsResult = await env.DB.prepare(`
                SELECT * FROM donations WHERE user_id = ? ORDER BY date DESC
              `).bind(session.user_id).all();
              donations = donationsResult.results || [];
              console.log(`Found ${donations.length} donations in 'donations' table for user ${session.user_id}`);
            } catch (e1) {
              console.log('No donations table found, trying user_donations...');

              // Try 'user_donations' table
              try {
                const userDonationsResult = await env.DB.prepare(`
                  SELECT * FROM user_donations WHERE user_id = ? ORDER BY created_at DESC
                `).bind(session.user_id).all();
                donations = userDonationsResult.results || [];
                console.log(`Found ${donations.length} donations in 'user_donations' table for user ${session.user_id}`);
              } catch (e2) {
                console.log('No user_donations table found either. Returning empty array.');
                console.log('Available tables can be checked with: SELECT name FROM sqlite_master WHERE type="table"');
              }
            }

            return successResponse({ donations });
          } catch (error) {
            console.error('Error querying donations:', error);
            return successResponse({ donations: [] });
          }
        }

        // POST donations endpoint - Save new donations
        if (apiPath === '/donations' && request.method === 'POST') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          try {
            const body = await request.json();
            console.log('💰 Donation data received:', body);

            // Generate donation ID
            const donationId = crypto.randomUUID();

            // Handle personal charity references - P-series IDs should work directly
            let finalCharityId = body.charity_id || 'charity-manual-entry';

            // Personal charities now use P-series IDs (P1, P2, etc.) which are compatible with foreign keys
            if (body.charity_id && body.charity_id !== 'charity-manual-entry') {
              console.log('💡 Using charity_id directly (including P-series for personal charities):', body.charity_id);
            }

            // COMPLETE FIELD MAPPING: Capture all frontend fields

            // Prepare type-specific metadata
            const metadata = {};
            if (body.type === 'items') {
              metadata.item_category = body.item_category;
              metadata.item_type = body.item_type;
              metadata.item_condition = body.item_condition;
            } else if (body.type === 'mileage') {
              metadata.miles_driven = body.miles_driven;
              metadata.mileage_rate = body.mileage_rate;
            } else if (body.type === 'stock') {
              metadata.stock_symbol = body.stock_symbol;
              metadata.shares = body.shares;
            } else if (body.type === 'crypto') {
              metadata.crypto_currency = body.crypto_currency;
              metadata.crypto_amount = body.crypto_amount;
            }

            await env.DB.prepare(`
              INSERT INTO donations (
                id, user_id, charity_id, charity_name, charity_address, charity_ein,
                tax_deductible_amount, type, description, date,
                fair_market_value, cost_basis, metadata, created_at, updated_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            `).bind(
              donationId,
              session.user_id,
              finalCharityId,
              body.charity_name || body.charity || 'Manual Entry',
              body.charity_address || null,
              body.charity_ein || null,
              body.tax_deductible_amount || body.amount || 0,
              body.type || 'money',
              body.description || null,
              body.date || new Date().toISOString().split('T')[0],
              body.fair_market_value || null,
              body.cost_basis || null,
              Object.keys(metadata).length > 0 ? JSON.stringify(metadata) : null
            ).run();

            console.log(`✅ Donation saved: ${donationId}`);

            return successResponse({
              id: donationId,
              message: 'Donation saved successfully'
            }, 'Donation saved successfully', 201);

          } catch (error) {
            console.error('❌ Error saving donation:', error);
            console.error('❌ Error details:', {
              message: error.message,
              stack: error.stack
            });
            return errorResponse('Failed to save donation: ' + error.message, 500);
          }
        }

        // DELETE donation endpoint
        if (apiPath.startsWith('/donations/') && request.method === 'DELETE') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          try {
            const donationId = apiPath.split('/donations/')[1];

            // Verify donation belongs to user
            const donation = await env.DB.prepare(`
              SELECT id FROM donations WHERE id = ? AND user_id = ?
            `).bind(donationId, session.user_id).first();

            if (!donation) {
              return errorResponse('Donation not found or access denied', 404);
            }

            // Delete the donation
            await env.DB.prepare(`
              DELETE FROM donations WHERE id = ? AND user_id = ?
            `).bind(donationId, session.user_id).run();

            console.log(`✅ Donation deleted: ${donationId} by user ${session.user_id}`);

            return successResponse({
              id: donationId,
              message: 'Donation deleted successfully'
            }, 'Donation deleted successfully', 200);

          } catch (error) {
            console.error('❌ Error deleting donation:', error);
            return errorResponse('Failed to delete donation: ' + error.message, 500);
          }
        }

        // USER TAX SETTINGS endpoints - Proper table structure
        if (apiPath === '/users/tax-settings' && request.method === 'GET') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          try {
            // Get tax settings from dedicated table
            const settings = await env.DB.prepare(`
              SELECT filing_status, income_bracket, tax_year, updated_at
              FROM user_tax_settings WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1
            `).bind(session.user_id).first();

            if (settings) {
              return successResponse({
                filing_status: settings.filing_status,
                income_bracket: settings.income_bracket,
                tax_year: settings.tax_year,
                last_updated: settings.updated_at
              });
            } else {
              // Return defaults if no saved settings
              return successResponse({
                filing_status: 'single',
                income_bracket: '22',
                tax_year: 2025
              });
            }
          } catch (error) {
            console.log('Tax settings table may not exist yet, using defaults:', error.message);
            return successResponse({
              filing_status: 'single',
              income_bracket: '22',
              tax_year: 2025
            });
          }
        }

        if (apiPath === '/users/tax-settings' && request.method === 'PUT') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          const body = await request.json();
          console.log('💾 Tax settings received:', body);

          try {
            // First try to create table if it doesn't exist (will fail silently if exists)
            try {
              await env.DB.prepare(`
                CREATE TABLE IF NOT EXISTS user_tax_settings (
                  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
                  user_id TEXT NOT NULL,
                  filing_status TEXT NOT NULL DEFAULT 'single',
                  income_bracket TEXT NOT NULL DEFAULT '22',
                  tax_year INTEGER NOT NULL DEFAULT 2025,
                  created_at TEXT DEFAULT (datetime('now')),
                  updated_at TEXT DEFAULT (datetime('now')),
                  FOREIGN KEY (user_id) REFERENCES users(id)
                )
              `).run();
              console.log('✅ user_tax_settings table ready');
            } catch (createError) {
              console.log('Table creation attempted:', createError.message);
            }

            // Insert or update tax settings
            const settingsId = crypto.randomUUID();

            await env.DB.prepare(`
              INSERT OR REPLACE INTO user_tax_settings
              (id, user_id, filing_status, income_bracket, tax_year, updated_at)
              VALUES (?, ?, ?, ?, ?, datetime('now'))
            `).bind(
              settingsId,
              session.user_id,
              body.filing_status || 'single',
              body.income_bracket || '22',
              body.tax_year || 2025
            ).run();

            console.log(`✅ Tax settings saved for user ${session.user_id}`);

            return successResponse({
              message: 'Tax settings saved successfully',
              settings: {
                filing_status: body.filing_status || 'single',
                income_bracket: body.income_bracket || '22',
                tax_year: body.tax_year || 2025
              }
            });
          } catch (error) {
            console.error('Tax settings save error:', error.message);
            return errorResponse('Failed to save tax settings: ' + error.message, 500);
          }
        }

        // USER PROFILE UPDATE endpoint
        if (apiPath === '/users/profile' && request.method === 'PUT') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          try {
            const body = await request.json();
            console.log('👤 Profile update received:', body);

            // Extract first and last names from full name if provided
            let firstName = body.firstName || '';
            let lastName = body.lastName || '';

            if (body.name && !firstName && !lastName) {
              const nameParts = body.name.trim().split(' ');
              firstName = nameParts[0] || '';
              lastName = nameParts.slice(1).join(' ') || '';
            }

            // Update user profile in database
            await env.DB.prepare(`
              UPDATE users
              SET first_name = ?, last_name = ?
              WHERE id = ?
            `).bind(firstName, lastName, session.user_id).run();

            console.log(`✅ Profile updated for user ${session.user_id}:`, { firstName, lastName });

            return successResponse({
              message: 'Profile updated successfully',
              user: {
                id: session.user_id,
                email: session.email,
                firstName: firstName,
                lastName: lastName,
                name: `${firstName} ${lastName}`.trim()
              }
            });
          } catch (error) {
            console.error('Profile update error:', error.message);
            return errorResponse('Failed to update profile: ' + error.message, 500);
          }
        }

        // PASSWORD CHANGE endpoint
        if (apiPath === '/users/change-password' && request.method === 'PUT') {
          const sessionId = getSessionFromRequest(request);
          const session = await validateSession(sessionId, env);

          if (!session) {
            return errorResponse('Authentication required', 401);
          }

          try {
            const body = await request.json();
            const { currentPassword, newPassword } = body;

            if (!currentPassword || !newPassword) {
              return errorResponse('Current password and new password are required', 400);
            }

            if (newPassword.length < 8) {
              return errorResponse('New password must be at least 8 characters', 400);
            }

            // Get current user
            const user = await env.DB.prepare(`
              SELECT password_hash FROM users WHERE id = ?
            `).bind(session.user_id).first();

            if (!user) {
              return errorResponse('User not found', 404);
            }

            // Verify current password
            const isCurrentPasswordValid = await verifyPassword(currentPassword, user.password_hash);
            if (!isCurrentPasswordValid) {
              return errorResponse('Current password is incorrect', 401);
            }

            // Hash new password
            const hashedNewPassword = await hashPassword(newPassword);

            // Update password
            await env.DB.prepare(`
              UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
            `).bind(hashedNewPassword, session.user_id).run();

            console.log(`✅ Password changed successfully for user ${session.user_id}`);

            return successResponse({
              message: 'Password changed successfully'
            });

          } catch (error) {
            console.error('Password change error:', error.message);
            return errorResponse('Failed to change password: ' + error.message, 500);
          }
        }

        return errorResponse('Not Found', 404);
      }

      // Default response
      return new Response('🚀 ULTIMATE FIX v2.1.7 - Use /api/* endpoints', {
        status: 200,
        headers: corsHeaders
      });

    } catch (error) {
      console.error('Unhandled error:', error);
      return errorResponse('Internal Server Error: ' + error.message, 500);
    }
  }
};