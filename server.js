const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Parse DATABASE_URL
function parseDatabaseUrl(url) {
    // URL format: postgresql://user:password@host:port/database
    const result = {
        user: '',
        password: '',
        host: '',
        port: 5432,
        database: ''
    };

    // Extract user and password
    const atIndex = url.indexOf('@');
    const protocolEnd = url.indexOf('://') + 3;
    const credentials = url.substring(protocolEnd, atIndex);
    const [user, password] = credentials.split(':');
    result.user = user;
    result.password = password;

    // Extract host, port, database
    const afterAt = url.substring(atIndex + 1);
    const portIndex = afterAt.indexOf('/');
    const hostPort = afterAt.substring(0, portIndex);
    const colonIndex = hostPort.lastIndexOf(':');

    if (colonIndex > -1) {
        result.host = hostPort.substring(0, colonIndex);
        result.port = parseInt(hostPort.substring(colonIndex + 1));
    } else {
        result.host = hostPort;
    }

    result.database = afterAt.substring(portIndex + 1);

    return result;
}

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database connection pool
let pool;

async function initDB() {
    const dbConfig = parseDatabaseUrl(process.env.DATABASE_URL);

    if (!dbConfig) {
        throw new Error('Invalid DATABASE_URL format');
    }

    pool = new Pool({
        host: dbConfig.host,
        user: dbConfig.user,
        password: dbConfig.password,
        database: 'kodbank',
        port: dbConfig.port,
        ssl: {
            rejectUnauthorized: false
        }
    });
    console.log('Database connection pool created');
}

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'kodbank_super_secret_key_2024_secure';

// ==================== API ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Kodbank API is running' });
});

// ==================== REGISTRATION ====================
app.post('/api/register', async (req, res) => {
    try {
        const { uid, username, password, email, phone, role } = req.body;

        // Validation
        if (!uid || !username || !password || !email) {
            return res.status(400).json({ success: false, message: 'Please provide all required fields' });
        }

        // Check if role is valid (only Customer allowed)
        if (role && role !== 'Customer') {
            return res.status(400).json({ success: false, message: 'Only Customer role is allowed for registration' });
        }

        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT * FROM KodUser WHERE username = $1 OR email = $2',
            [username, email]
        );
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'Username or email already exists' });
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

        res.json({ success: true, message: 'Registration successful! Please login.' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Registration failed. Please try again.' });
    }
});

// ==================== LOGIN ====================
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Please provide username and password' });
        }

        // Find user
        const users = await pool.query('SELECT * FROM KodUser WHERE username = $1', [username]);
        if (users.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Invalid username or password' });
        }

        const user = users.rows[0];

        // Compare password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Invalid username or password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { username: user.username, role: user.role, uid: user.uid },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Calculate expiry (24 hours from now)
        const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

        // Store token in database
        await pool.query(
            'INSERT INTO UserToken (token, uid, expiry) VALUES ($1, $2, $3)',
            [token, user.uid, expiry]
        );

        // Set cookie with token
        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            sameSite: 'lax'
        });

        res.json({
            success: true,
            message: 'Login successful!',
            token: token,
            user: { username: user.username, role: user.role, uid: user.uid }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Login failed. Please try again.' });
    }
});

// ==================== CHECK BALANCE ====================
app.get('/api/balance', async (req, res) => {
    try {
        // Get token from cookie or Authorization header
        const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided. Please login.' });
        }

        // Verify token
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ success: false, message: 'Token expired. Please login again.' });
            }
            return res.status(401).json({ success: false, message: 'Invalid token. Please login.' });
        }

        // Check if token exists in database and not expired
        const tokens = await pool.query(
            'SELECT * FROM UserToken WHERE token = $1 AND uid = $2 AND expiry > NOW()',
            [token, decoded.uid]
        );

        if (tokens.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Token expired or invalid. Please login again.' });
        }

        // Get user balance
        const users = await pool.query('SELECT balance, username FROM KodUser WHERE uid = $1', [decoded.uid]);

        if (users.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.json({
            success: true,
            balance: users.rows[0].balance,
            username: users.rows[0].username
        });
    } catch (error) {
        console.error('Balance check error:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch balance. Please try again.' });
    }
});

// ==================== LOGOUT ====================
app.post('/api/logout', async (req, res) => {
    try {
        const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

        if (token) {
            // Delete token from database
            await pool.query('DELETE FROM UserToken WHERE token = $1', [token]);
        }

        // Clear cookie
        res.clearCookie('token');

        res.json({ success: true, message: 'Logout successful' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ success: false, message: 'Logout failed' });
    }
});

// ==================== FRONTEND ROUTES ====================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/userdashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start server
async function startServer() {
    try {
        await initDB();
        app.listen(PORT, () => {
            console.log(`Kodbank server running on http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
