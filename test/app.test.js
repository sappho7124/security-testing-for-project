const request = require('supertest');
const express = require('express');
const app = require('../index'); // Adjust path to your app file

describe('API Endpoints', () => {
  it('GET / should return server status', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toEqual(200);
    expect(res.text).toBe('Server is running and ready for the diabetes management app!');
  });

  it('POST /register should register a user', async () => {
    const res = await request(app).post('/register').send({
      email: 'test@example.com',
      password: 'securepassword',
    });
    expect(res.statusCode).toEqual(201);
    expect(res.body.message).toBe('User registered successfully.');
  });

  it('POST /login should log in a user', async () => {
    // Register first
    await request(app).post('/register').send({
      email: 'login@example.com',
      password: 'securepassword',
    });

    // Then log in
    const res = await request(app).post('/login').send({
      email: 'login@example.com',
      password: 'securepassword',
    });
    expect(res.statusCode).toEqual(200);
    expect(res.body.message).toBe('Login successful.');
  });

  it('POST /health-metrics should add health metrics', async () => {
    const res = await request(app).post('/health-metrics').send({
      email: 'test@example.com',
      glucoseLevel: 120,
      bloodPressure: '120/80',
    });
    expect(res.statusCode).toEqual(201);
    expect(res.body.message).toBe('Health metrics stored securely.');
  });

  it('GET /audit-logs should return audit logs', async () => {
    const res = await request(app).get('/audit-logs');
    expect(res.statusCode).toEqual(200);
    expect(Array.isArray(res.body)).toBeTruthy();
  });
});
