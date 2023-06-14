const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const mysql = require('mysql');

// Create MySQL connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'ecom'
});

const app = express();
app.use(bodyParser.json());

// Middleware to authenticate API key or access token
function authenticate(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (apiKey === 'Aspire@123' || token) {
    // If API key or access token is present, proceed to the next middleware
    next();
  } else {
    return res.status(401).json({ error: 'Invalid API key or access token' });
  }
}

// Middleware to authenticate access token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access token not found' });
  }

  jwt.verify(token, 'key_32_+_honi_chaiya', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid access token' });
    }
    req.user = user;
    next();
  });
}

// Middleware to authenticate refresh token
function authenticateRefreshToken(req, res, next) {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token not found' });
  }

  jwt.verify(refreshToken, 'refresh_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }
    req.user = user;
    next();
  });
}

// Login route - returns access token and refresh token
app.post('/login', (req, res) => {
  const { retaile_id, password } = req.body;

  // Authenticate the user in the database
  pool.query('SELECT retaile_id, password, status, owner_name FROM retailer_registration WHERE retaile_id = ? AND password = ?', [retaile_id, password], (error, results) => {
    if (error) {
      console.error('Database query error:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid retailer ID or password' });
    }

    // If authentication successful, generate and return access token and refresh token
    const accessToken = jwt.sign({ retaile_id }, 'key_32_+_honi_chaiya', { expiresIn: '15m' });
    const refreshToken = jwt.sign({ retaile_id }, 'refresh_secret_key', { expiresIn: '7d' });
    res.json({ accessToken, refreshToken});
  });
});

// Refresh token route - renews the access token
app.post('/refresh-token', authenticateRefreshToken, (req, res) => {
  const { retaile_id } = req.material;

  // Generate new access token
  const accessToken = jwt.sign({ retaile_id }, 'key_32_+_honi_chaiya', { expiresIn: '15m' });
  res.json({ accessToken });
});

// API endpoint that can be authenticated by either API key or access token
app.get('/api', authenticate, (req, res) => {
  res.json({ message: 'API authenticated successfully' });
 
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on port 3000 \n connected');
});
