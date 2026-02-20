const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

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
        const { uid, username, password, email, phone } = JSON.parse(event.body);

        // Validation
        if (!uid || !username || !password || !email) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Please provide all required fields: uid, username, password, email' })
            };
        }

        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT * FROM KodUser WHERE username = $1 OR email = $2',
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ success: false, message: 'Username or email already exists' })
            };
        }

        // Encrypt password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Default balance is 100000
        const defaultBalance = 100000.00;

        // Insert user
        await pool.query(
            'INSERT INTO KodUser (uid, username, email, password, balance, phone, role) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [uid, username, email, hashedPassword, defaultBalance, phone || '', 'Customer']
        );

        return {
            statusCode: 201,
            headers,
            body: JSON.stringify({ success: true, message: 'Registration successful! Please login.' })
        };
    } catch (error) {
        console.error('Registration error:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ success: false, message: 'Registration failed: ' + error.message })
        };
    }
};
