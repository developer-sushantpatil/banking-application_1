const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
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
        const { username, password } = JSON.parse(event.body);

        if (!username || !password) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Please provide username and password' })
            };
        }

        // Find user
        const users = await pool.query('SELECT * FROM KodUser WHERE username = $1', [username]);

        if (users.rows.length === 0) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ success: false, message: 'Invalid username or password' })
            };
        }

        const user = users.rows[0];

        // Compare password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return {
                statusCode: 401,
                headers,
                body: JSON.stringify({ success: false, message: 'Invalid username or password' })
            };
        }

        // Generate JWT token with username as Subject and role as Claim
        const token = jwt.sign(
            { username: user.username, role: user.role, uid: user.uid },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Calculate expiry (24 hours from now)
        const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

        // Store JWT token in UserToken table
        await pool.query(
            'INSERT INTO UserToken (token, uid, expiry) VALUES ($1, $2, $3)',
            [token, user.uid, expiry]
        );

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                message: 'Login successful!',
                token: token,
                user: { username: user.username, role: user.role, uid: user.uid }
            })
        };
    } catch (error) {
        console.error('Login error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Login failed: ' + error.message })
        };
    }
};
