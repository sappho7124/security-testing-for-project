const request = require('supertest');
const app = require('../index'); // Adjust path to your app file

describe('API Endpoints with Logging', () => {
  it('GET / should return server status', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toEqual(200);
    expect(res.text).toBe('Server is running and ready for the diabetes management app!');
  });

  it('POST /register should register a user and log the action', async () => {
    const res = await request(app).post('/register').send({
      email: 'test@example.com',
      password: 'securepassword',
    });
    expect(res.statusCode).toEqual(201);
    expect(res.body.message).toBe('User registered successfully.');
  });

  it('POST /login should log in a user and log the action', async () => {
    // Ensure the user is registered
    await request(app).post('/register').send({
      email: 'login@example.com',
      password: 'securepassword',
    });

    const res = await request(app).post('/login').send({
      email: 'login@example.com',
      password: 'securepassword',
    });
    expect(res.statusCode).toEqual(200);
    expect(res.body.message).toBe('Login successful.');
  });

  it('POST /health-metrics should add health metrics and log the action', async () => {
    const res = await request(app).post('/health-metrics').send({
      email: 'test@example.com',
      glucoseLevel: 120,
      bloodPressure: '120/80',
    });
    expect(res.statusCode).toEqual(201);
    expect(res.body.message).toBe('Health metrics stored securely.');
  });

  it('GET /audit-logs should include test actions', async () => {
    const res = await request(app).get('/audit-logs');
    expect(res.statusCode).toEqual(200);
    const logs = res.body;

    // Ensure the test actions are logged
    expect(logs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ action: 'User Registered', email: 'test@example.com' }),
        expect.objectContaining({ action: 'User Login', email: 'login@example.com' }),
        expect.objectContaining({ action: 'Health Metrics Added', email: 'test@example.com' }),
      ])
    );
  });
});
