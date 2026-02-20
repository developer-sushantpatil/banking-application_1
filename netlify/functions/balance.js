const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

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

const JWT_SECRET = process.env.JWT_SECRET || 'kodbank_super_secret_key_2024_secire';

// CORS headers
const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

exports.handler = async function (event, context) {
    // Handle CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'GET') {
        return { statusCode: 405, headers, body: JSON.stringify({ error: 'Method not allowed' }) };
    }

    try {
        // Get JWT token from request header
        const token = event.headers.authorization?.split(' ')[1];

        if (!token) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ success: false, message: 'No token provided. Please login.' })
            };
        }

        // Verify JWT token signature
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return {
                    statusCode: 401,
                    headers,
                    body: JSON.stringify({ success: false, message: 'Token expired. Please login again.' })
                };
            }
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ success: false, message: 'Invalid token. Please login.' })
            };
        }

        // Check token expiry in database
        const tokens = await pool.query(
            'SELECT * FROM UserToken WHERE token = $1 AND uid = $2 AND expiry > NOW()',
            [token, decoded.uid]
        );

        if (tokens.rows.length === 0) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ success: false, message: 'Token expired or invalid. Please login again.' })
            };
        }

        // Fetch balance from KodUser table using username from token
        const users = await pool.query(
            'SELECT balance, username FROM KodUser WHERE uid = $1',
            [decoded.uid]
        );

        if (users.rows.length === 0) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ success: false, message: 'User not found' })
            };
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                balance: users.rows[0].balance,
                username: users.rows[0].username
            })
        };
    } catch (error) {
        console.error('Balance check error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Failed to fetch balance: ' + error.message })
        };
    }
};
