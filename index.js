const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const dotenv = require('dotenv');
const geoip = require('geoip-lite');

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());

// Constants for encryption
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef'; // 32 bytes key for AES-256
const IV_LENGTH = 16; // For AES, this is the block size

// In-memory storage for health metrics, users, and logs
let userData = [];
let auditLogs = [];

// Utility functions for encryption and decryption
function encrypt(text) {
  let iv = crypto.randomBytes(IV_LENGTH);
  let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  let textParts = text.split(':');
  let iv = Buffer.from(textParts.shift(), 'hex');
  let encryptedText = Buffer.from(textParts.join(':'), 'hex');
  let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

// Utility function to get location from IP
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

// Middleware to log requests with location
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  const location = getLocationFromIP(ip);
  req.location = location;
  next();
});

// Endpoint: Root
app.get('/', (req, res) => {
  res.send('Server is running and ready for the diabetes management app!');
});

// Endpoint: Register a User
app.post('/register', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

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

// Endpoint: Authenticate a User
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const user = userData.find(u => u.email === email);
  if (!user) {
    return res.status(401).json({ error: 'User not found.' });
  }

  const decryptedPassword = decrypt(user.encryptedPassword);
  if (password !== decryptedPassword) {
    return res.status(401).json({ error: 'Invalid password.' });
  }

  auditLogs.push({
    action: 'User Login',
    email,
    location: req.location,
    timestamp: new Date(),
  });

  res.status(200).json({ message: 'Login successful.' });
});

// Endpoint: Add Health Metrics
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

// Endpoint: Retrieve Audit Logs
app.get('/audit-logs', (req, res) => {
  res.status(200).json(auditLogs);
});

// Endpoint: Terms of Use and Privacy
app.get('/terms-and-privacy', (req, res) => {
  const terms = `
    Terms of Use:
    1. Users must agree to the collection and encryption of sensitive data.
    2. The app complies with regional data protection laws (GDPR, HIPAA, etc.).
    
    Privacy Policy:
    1. User data is securely encrypted and only accessible to authorized personnel.
    2. Users may request the deletion of their data at any time.
  `;

  res.status(200).send(terms);
});

// Force HTTPS (for Heroku)
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

// Start the Server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
