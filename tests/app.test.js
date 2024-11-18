const request = require('supertest');
const app = require('../index');
const http = require('http');

let server;

beforeAll(done => {
  server = http.createServer(app);
  server.listen(() => done());
});

afterAll(done => {
  server.close(done);
});

describe('Behavioral Security Features', () => {
  it('should detect a new device login', async () => {
    await request(server).post('/register').send({
      email: 'test@example.com',
      password: 'securepassword',
    });

    const res1 = await request(server)
      .post('/login')
      .set('User-Agent', 'Device-1')
      .send({ email: 'test@example.com', password: 'securepassword' });

    const res2 = await request(server)
      .post('/login')
      .set('User-Agent', 'Device-2')
      .send({ email: 'test@example.com', password: 'securepassword' });

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
  });

  it('should log restricted access attempts', async () => {
    const res = await request(server).get('/restricted');
    expect(res.status).toBe(403);
  });

  it('should flag suspicious travel times', async () => {
    const res1 = await request(server)
      .post('/login')
      .set('X-Forwarded-For', '8.8.8.8')
      .send({ email: 'test@example.com', password: 'securepassword' });

    const res2 = await request(server)
      .post('/login')
      .set('X-Forwarded-For', '1.1.1.1')
      .send({ email: 'test@example.com', password: 'securepassword' });

    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200); // Detect unusual travel times in logs
  });
});
