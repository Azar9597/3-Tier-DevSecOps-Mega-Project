const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const userRoutes = require('./routes/userRoutes');
const authRoutes = require('./routes/authRoutes');
const db = require('./models/db'); // MySQL pool connection

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

/* =====================================================
   🔴 BUG 1: SQL Injection Vulnerability (INTENTIONAL)
   SonarQube WILL flag this as a Vulnerability
===================================================== */
app.get('/api/user', async (req, res) => {
  const userId = req.query.id;

  // ❌ Vulnerable SQL (string concatenation)
  const query = "SELECT * FROM users WHERE id = " + userId;

  const [rows] = await db.promise().query(query);
  res.json(rows);
});

/* =====================================================
   🚨 BUG 2: eval() usage (Security Hotspot)
   SonarQube WILL flag this as a Security Hotspot
===================================================== */
app.get('/api/run', (req, res) => {
  const code = req.query.code;

  // ❌ Dangerous use of eval
  eval(code);

  res.send("Code executed");
});

// Function to wait until MySQL is ready
const waitForDb = async (retries = 30, delay = 2000) => {
  while (retries > 0) {
    try {
      const [rows] = await db.promise().query("SHOW TABLES LIKE 'users'");
      if (rows.length > 0) {
        console.log('✅ MySQL `users` table found.');
        return;
      }
      console.log(`⏳ Waiting for MySQL (users table)... Retries left: ${retries}`);
    } catch (err) {
      console.error(`🔴 MySQL query failed: ${err.message}`);
    }

    retries--;
    await new Promise(res => setTimeout(res, delay));
  }
  throw new Error('❌ MySQL `users` table not available after multiple retries.');
};

// Function to seed admin user if not exists
const seedAdminUser = async () => {
  const name = process.env.ADMIN_NAME || 'Admin User';
  const email = process.env.ADMIN_EMAIL || 'admin@example.com';
  const password = process.env.ADMIN_PASSWORD || 'admin123';
  const role = process.env.ADMIN_ROLE || 'admin';

  try {
    const [existing] = await db.promise().query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (existing.length === 0) {
      const hashed = await bcrypt.hash(password, 10);
      await db.promise().query(
        'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
        [name, email, hashed, role]
      );
      console.log(`✅ Admin user created → ${email}`);
    } else {
      console.log(`ℹ️ Admin user already exists → ${email}`);
    }
  } catch (err) {
    console.error(`❌ Admin seeding failed: ${err.message}`);
  }
};

// Start server
(async () => {
  try {
    await waitForDb();
    await seedAdminUser();

    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
    });
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
})();
