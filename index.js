const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
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

// Multer setup for file uploads
const upload = multer({ dest: 'uploads/' });

// In-memory storage
let userData = [];
let auditLogs = [];
let failedLoginAttempts = {};

// Data Retention Policies
const DATA_RETENTION_PERIOD_MS = 180 * 24 * 60 * 60 * 1000; // 180 days

function enforceDataRetention() {
  const now = Date.now();
  auditLogs = auditLogs.filter(log => now - new Date(log.timestamp).getTime() <= DATA_RETENTION_PERIOD_MS);
}
setInterval(enforceDataRetention, 24 * 60 * 60 * 1000); // Run daily

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

function logAudit(action, email, location, details = null) {
  const log = {
    action,
    email,
    location,
    timestamp: new Date(),
    ...(details ? { details } : {}),
  };
  auditLogs.push(log);
  console.log(JSON.stringify(log, null, 2)); // Log to console for debugging/testing
}

// Middleware to log requests with location
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  req.location = geoip.lookup(ip) || { city: 'Unknown', country: 'Unknown' };
  next();
});

// Restricted access test endpoint
app.get('/restricted', (req, res) => {
    logAudit('Unauthorized Access Attempt', 'Unknown', req.location);
    res.status(403).json({ message: 'Access denied to restricted area.' });
  });
  

// Dashboard to view audit logs
app.get('/dashboard', (req, res) => {
  const logs = auditLogs.map(log => `<li>${JSON.stringify(log)}</li>`).join('');
  const dashboardHTML = `
    <html>
      <head><title>Request Dashboard</title></head>
      <body>
        <h1>Request Logs Dashboard</h1>
        <ul>${logs}</ul>
      </body>
    </html>
  `;
  res.send(dashboardHTML);
});

// Simulate JSON file processing
app.post('/upload-json', upload.single('file'), (req, res) => {
  const { email } = req.body;

  if (!email || !req.file) {
    return res.status(400).json({ error: 'Email and file are required.' });
  }

  const filePath = path.resolve(__dirname, req.file.path);
  const fileContent = fs.readFileSync(filePath, 'utf-8');

  try {
    const data = JSON.parse(fileContent);

    const encryptedData = {
      name: encrypt(data.name),
      healthMetrics: encrypt(JSON.stringify(data.healthMetrics)),
    };

    logAudit('JSON File Uploaded', email, req.location, { fileName: req.file.originalname });
    res.status(201).json({ message: 'File processed successfully.', encryptedData });

    fs.unlinkSync(filePath);
  } catch (error) {
    fs.unlinkSync(filePath);
    logAudit('Invalid JSON File Upload Attempt', email, req.location, { error: error.message });
    return res.status(400).json({ error: 'Invalid JSON file.' });
  }
});

// Register endpoint
app.post('/register', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

  const encryptedPassword = encrypt(password);
  userData.push({ email, encryptedPassword });

  logAudit('User Registered', email, req.location);
  res.status(201).json({ message: 'User registered successfully.' });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const user = userData.find(u => u.email === email);
  if (!user) {
    logAudit('Failed Login: User Not Found', email, req.location);
    return res.status(401).json({ error: 'User not found.' });
  }

  const decryptedPassword = decrypt(user.encryptedPassword);
  if (password !== decryptedPassword) {
    failedLoginAttempts[email] = (failedLoginAttempts[email] || 0) + 1;

    if (failedLoginAttempts[email] > 5) {
      logAudit('Brute Force Prevention Triggered', email, req.location);
      return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
    }

    logAudit('Failed Login: Incorrect Password', email, req.location);
    return res.status(401).json({ error: 'Invalid password.' });
  }

  failedLoginAttempts[email] = 0;
  logAudit('User Login', email, req.location);
  res.status(200).json({ message: 'Login successful.' });
});

// Add health metrics endpoint
app.post('/health-metrics', (req, res) => {
  try {
    const { email, glucoseLevel, bloodPressure } = req.body;

    if (!email || !glucoseLevel || !bloodPressure) {
      throw new Error('Missing required fields.');
    }

    const encryptedGlucose = encrypt(glucoseLevel.toString());
    const encryptedBloodPressure = encrypt(bloodPressure.toString());

    logAudit('Health Metrics Submitted', email, req.location);
    res.status(201).json({ message: 'Metrics stored securely.', encryptedData: { encryptedGlucose, encryptedBloodPressure } });
  } catch (error) {
    logAudit('Failed Health Metrics Submission', req.body.email || 'Unknown', req.location, { error: error.message });
    res.status(400).json({ error: error.message });
  }
});

// Endpoint to view audit logs
app.get('/audit-logs', (req, res) => {
  res.status(200).json(auditLogs);
});

// Start server if not in test mode
if (require.main === module) {
  app.listen(port, () => console.log(`Server running on port ${port}`));
}

module.exports = app;
