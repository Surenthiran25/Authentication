import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// Initialize SQLite database
const db = new sqlite3.Database(join(__dirname, 'database.sqlite'), (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Initialize database tables
function initializeDatabase() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      reset_token TEXT,
      reset_token_expires DATETIME
    )
  `);
}

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });
});

// Forgot password endpoint
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour

    db.run(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE email = ?',
      [resetToken, resetTokenExpires.toISOString(), email],
      async (err) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
        
        try {
          await transporter.sendMail({
            to: email,
            subject: 'Password Reset Request',
            html: `
              <p>You requested a password reset.</p>
              <p>Click this <a href="${resetUrl}">link</a> to reset your password.</p>
              <p>If you didn't request this, please ignore this email.</p>
              <p>This link will expire in 1 hour.</p>
            `
          });

          res.json({ message: 'Password reset email sent' });
        } catch (error) {
          console.error('Email error:', error);
          res.status(500).json({ error: 'Failed to send reset email' });
        }
      }
    );
  });
});

// Reset password endpoint
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;

  db.get(
    'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > datetime("now")',
    [token],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        return res.status(400).json({ error: 'Invalid or expired reset token' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.run(
        'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
        [hashedPassword, user.id],
        (err) => {
          if (err) {
            return res.status(500).json({ error: 'Failed to update password' });
          }
          res.json({ message: 'Password updated successfully' });
        }
      );
    }
  );
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});