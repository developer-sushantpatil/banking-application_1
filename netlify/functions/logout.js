const { Pool } = require('pg');

// Parse DATABASE_URL if provided
let pool;
const dbUrl = process.env.DATABASE_URL;

if (dbUrl) {
    const match = dbUrl.match(/postgresql:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\/(\d+)/);
    if (match) {
        pool = new Pool({
            host: match[3],
            user: match[1],
            password: match[2],
            port: parseInt(match[4]),
            database: 'kodbank',
            ssl: { rejectUnauthorized: false }
        });
    }
} else {
    pool = new Pool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || 'kodbank',
        port: parseInt(process.env.DB_PORT) || 5432,
        ssl: { rejectUnauthorized: false }
    });
}

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
