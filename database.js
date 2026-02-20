const { Pool } = require('pg');
require('dotenv').config();

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

async function setupDatabase() {
  const dbConfig = parseDatabaseUrl(process.env.DATABASE_URL);

  if (!dbConfig) {
    console.error('Invalid DATABASE_URL format');
    process.exit(1);
  }

  // Connect to postgres database first to create our database
  const pool = new Pool({
    host: dbConfig.host,
    user: dbConfig.user,
    password: dbConfig.password,
    database: 'postgres',
    port: dbConfig.port,
    ssl: {
      rejectUnauthorized: false
    }
  });

  console.log('Connected to PostgreSQL server');

  try {
    // Check if kodbank database exists, if not create it
    const dbCheck = await pool.query(
      "SELECT 1 FROM pg_database WHERE datname = 'kodbank'"
    );

    if (dbCheck.rows.length === 0) {
      await pool.query('CREATE DATABASE kodbank');
      console.log("Database 'kodbank' created");
    }
  } catch (err) {
    console.log('Database may already exist or error creating:', err.message);
  }

  // Close the pool and reconnect to kodbank
  await pool.end();

  // Now connect to kodbank database
  const appPool = new Pool({
    host: dbConfig.host,
    user: dbConfig.user,
    password: dbConfig.password,
    database: 'kodbank',
    port: dbConfig.port,
    ssl: {
      rejectUnauthorized: false
    }
  });

  // Create KodUser table
  await appPool.query(`
    CREATE TABLE IF NOT EXISTS KodUser (
      uid VARCHAR(50) PRIMARY KEY,
      username VARCHAR(100) NOT NULL UNIQUE,
      email VARCHAR(100) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      balance DECIMAL(15, 2) DEFAULT 100000.00,
      phone VARCHAR(20),
      role VARCHAR(20) DEFAULT 'Customer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  console.log('KodUser table created or already exists');

  // Create UserToken table
  await appPool.query(`
    CREATE TABLE IF NOT EXISTS UserToken (
      tid SERIAL PRIMARY KEY,
      token TEXT NOT NULL,
      uid VARCHAR(50) NOT NULL,
      expiry TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (uid) REFERENCES KodUser(uid) ON DELETE CASCADE
    )
  `);
  console.log('UserToken table created or already exists');

  await appPool.end();
  console.log('Database setup completed successfully!');
}

// Run if called directly
if (require.main === module) {
  setupDatabase()
    .then(() => process.exit(0))
    .catch(err => {
      console.error('Database setup failed:', err);
      process.exit(1);
    });
}

module.exports = setupDatabase;
