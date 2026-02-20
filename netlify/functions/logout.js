const { Pool } = require('pg');

// Database configuration
const pool = new Pool({
    host: process.env.DB_HOST || 'db.otviepliqleobakgqyda.supabase.co',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'Sushantkod114',
    database: process.env.DB_NAME || 'kodbank',
    port: parseInt(process.env.DB_PORT) || 5432,
    ssl: { rejectUnauthorized: false }
});

// CORS headers
const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
};

exports.handler = async function (event, context) {
    // Handle CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
    }

    try {
        // Get JWT token from request header
        const token = event.headers.authorization?.split(' ')[1];

        if (token) {
            // Delete token from database
            await pool.query('DELETE FROM UserToken WHERE token = $1', [token]);
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true, message: 'Logout successful' })
        };
    } catch (error) {
        console.error('Logout error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Logout failed: ' + error.message })
        };
    }
};
