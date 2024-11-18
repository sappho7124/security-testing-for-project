const request = require('supertest');
const app = require('../index');
const http = require('http');
const fs = require('fs');
const path = require('path');

let server;

beforeAll(done => {
  server = http.createServer(app);
  server.listen(() => {
    console.log('Test server started');
    done();
  });
});

afterAll(done => {
  server.close(() => {
    console.log('Test server stopped');
    done();
  });
});

describe('Health App Comprehensive Tests', () => {
  it('should register a new user', async () => {
    console.log('Testing user registration...');
    const res = await request(server)
      .post('/register')
      .send({ email: 'newuser@example.com', password: 'securepassword' });

    expect(res.status).toBe(201);
    expect(res.body.message).toBe('User registered successfully.');
    console.log('User registration test passed.');
  });

  it('should process a valid JSON file upload', async () => {
    console.log('Testing valid JSON file upload...');
    const filePath = path.resolve(__dirname, 'valid.json');
    fs.writeFileSync(filePath, JSON.stringify({
      name: 'John Doe',
      healthMetrics: { glucose: 120, bloodPressure: '120/80' },
    }));

    const res = await request(server)
      .post('/upload-json')
      .field('email', 'test@example.com')
      .attach('file', filePath);

    fs.unlinkSync(filePath);

    expect(res.status).toBe(201);
    expect(res.body.message).toBe('File processed successfully.');
    console.log('Valid JSON file upload test passed.');
  });

  it('should reject a malformed JSON file', async () => {
    console.log('Testing malformed JSON file upload...');
    const filePath = path.resolve(__dirname, 'invalid.json');
    fs.writeFileSync(filePath, 'not JSON content');

    const res = await request(server)
      .post('/upload-json')
      .field('email', 'test@example.com')
      .attach('file', filePath);

    fs.unlinkSync(filePath);

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid JSON file.');
    console.log('Malformed JSON file upload test passed.');
  });

  it('should handle unauthorized restricted area access', async () => {
    console.log('Testing unauthorized access...');
    const res = await request(server).get('/restricted');
    expect(res.status).toBe(403);
    expect(res.body.message).toBe('Access denied to restricted area.');
    console.log('Unauthorized access test passed.');
  });

  it('should prevent brute-force login attempts', async () => {
    console.log('Testing brute-force prevention...');
    const user = { email: 'brute@example.com', password: 'password' };
    await request(server).post('/register').send(user);

    for (let i = 0; i < 5; i++) {
      await request(server).post('/login').send({ email: user.email, password: 'wrongpassword' });
    }

    const res = await request(server).post('/login').send({ email: user.email, password: 'wrongpassword' });

    expect(res.status).toBe(429);
    expect(res.body.error).toBe('Too many login attempts. Please try again later.');
    console.log('Brute-force prevention test passed.');
  });

  it('should enforce data retention policies', async () => {
    console.log('Testing data retention policy...');
    const initialLogCount = await request(server).get('/audit-logs').then(res => res.body.length);

    // Simulate log creation 181 days ago
    const oldLogDate = new Date(Date.now() - (181 * 24 * 60 * 60 * 1000));
    app.auditLogs.push({ action: 'Old Log', timestamp: oldLogDate });

    // Wait for data retention policy to clean logs
    await new Promise(resolve => setTimeout(resolve, 2000));

    const finalLogCount = await request(server).get('/audit-logs').then(res => res.body.length);
    expect(finalLogCount).toBe(initialLogCount); // Old logs should have been removed
    console.log('Data retention policy test passed.');
  });

  it('should perform stress testing with high requests', async () => {
    console.log('Performing stress test...');
    const stressTestPromises = Array(100).fill().map((_, i) => {
      const email = `stress${i}@example.com`;
      return request(server)
        .post('/register')
        .send({ email, password: 'stresspassword' });
    });

    const results = await Promise.all(stressTestPromises);
    results.forEach(res => {
      expect(res.status).toBe(201);
      expect(res.body.message).toBe('User registered successfully.');
    });

    console.log('Stress test passed.');
  });

  it('should log and audit all actions', async () => {
    console.log('Verifying audit logs...');
    const res = await request(server).get('/audit-logs');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
    console.log('Audit logs verification test passed.');
  });

  it('should display the dashboard', async () => {
    console.log('Testing dashboard display...');
    const res = await request(server).get('/dashboard');
    expect(res.status).toBe(200);
    expect(res.text).toContain('<html>');
    expect(res.text).toContain('<ul>');
    console.log('Dashboard test passed.');
  });
});
