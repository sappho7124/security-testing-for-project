const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const dotenv = require('dotenv');
const geoip = require('geoip-lite');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Constants for encryption
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef'; // 32 bytes key for AES-256
const IV_LENGTH = 16; // For AES, this is the block size

// In-memory storage
let userData = [];
let auditLogs = [];
let failedLoginAttempts = {}; // { email: { attempts: number, lastAttempt: timestamp } }
let knownDevices = {}; // { email: [deviceFingerprints] }
let restrictedAccessAttempts = {}; // { email: { endpoint: count } }

// Utility functions
function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(text) {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

function getLocationFromIP(ip) {
  const geo = geoip.lookup(ip);
  if (geo) {
    return {
      city: geo.city || 'Unknown',
      region: geo.region || 'Unknown',
      country: geo.country || 'Unknown',
    };
  }
  return { city: 'Unknown', region: 'Unknown', country: 'Unknown' };
}

function calculateTravelTime(location1, location2) {
  // Dummy function: Replace with actual distance calculation and travel time logic
  if (!location1 || !location2) return Infinity;
  return Math.random() * 1000; // Simulate time in seconds
}

// Middleware to log requests with location
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  req.location = getLocationFromIP(ip);
  req.deviceFingerprint = `${req.headers['user-agent']}-${req.connection.remotePort}`;
  next();
});

// Middleware for restricted access tracking
app.use((req, res, next) => {
  const { email } = req.body;
  if (!email) return next();

  if (!restrictedAccessAttempts[email]) restrictedAccessAttempts[email] = {};

  const endpoint = req.path;
  restrictedAccessAttempts[email][endpoint] = (restrictedAccessAttempts[email][endpoint] || 0) + 1;

  next();
});

// Register endpoint
app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const encryptedPassword = encrypt(password);
  userData.push({ email, encryptedPassword });

  auditLogs.push({
    action: 'User Registered',
    email,
    location: req.location,
    timestamp: new Date(),
  });

  res.status(201).json({ message: 'User registered successfully.' });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const user = userData.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'User not found.' });

  const decryptedPassword = decrypt(user.encryptedPassword);
  if (password !== decryptedPassword) return res.status(401).json({ error: 'Invalid password.' });

  // Device Fingerprinting
  knownDevices[email] = knownDevices[email] || [];
  if (!knownDevices[email].includes(req.deviceFingerprint)) {
    knownDevices[email].push(req.deviceFingerprint);
    auditLogs.push({
      action: 'New Device Detected',
      email,
      location: req.location,
      timestamp: new Date(),
    });
  }

  auditLogs.push({
    action: 'User Login',
    email,
    location: req.location,
    timestamp: new Date(),
  });

  res.status(200).json({ message: 'Login successful.' });
});

// Add health metrics endpoint
app.post('/health-metrics', (req, res) => {
  const { email, glucoseLevel, bloodPressure } = req.body;
  if (!email || !glucoseLevel || !bloodPressure) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const encryptedGlucose = encrypt(glucoseLevel.toString());
  const encryptedBloodPressure = encrypt(bloodPressure.toString());

  auditLogs.push({
    action: 'Health Metrics Added',
    email,
    location: req.location,
    timestamp: new Date(),
  });

  res.status(201).json({
    message: 'Health metrics stored securely.',
    encryptedData: { glucose: encryptedGlucose, bloodPressure: encryptedBloodPressure },
  });
});

// Audit logs endpoint
app.get('/audit-logs', (req, res) => {
  res.status(200).json(auditLogs);
});

// Restricted area endpoint
app.get('/restricted', (req, res) => {
  res.status(403).json({ message: 'Access denied to restricted area.' });
});

// Start server if not in test mode
if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}

module.exports = app;
