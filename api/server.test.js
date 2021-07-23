// Write your tests here
const request = require("supertest");
const server = require("./server");
const db = require("../data/dbConfig");
const bcrypt = require("bcryptjs");
const jwtDecode = require("jwt-decode");

beforeAll(async () => {
  await db.migrate.rollback();
  await db.migrate.latest();
});

afterAll(async () => {
  await db.destroy();
});

test("sanity", () => {
  expect(true).toBe(true);
});

describe("server.js", () => {
  describe("[POST] /api/auth/register", () => {
    it("[1] creates a new user", async () => {
      await request(server)
        .post("/api/auth/register")
        .send({ username: "roger", password: "1234" });
      const roger = await db("users").where("username", "roger").first();
      expect(roger).toMatchObject({ username: "roger" });
    });
    it("[2] saves password as hash rather than plain text", async () => {
      await request(server)
        .post("/api/auth/register")
        .send({ username: "sammy", password: "1234" });
      const sammy = await db("users").where("username", "sammy").first();
      expect(bcrypt.compareSync("1234", sammy.password)).toBeTruthy();
    });
    it("[3] responds with the right status on successful registration", async () => {
      const res = await request(server)
        .post("/api/auth/register")
        .send({ username: "claire", password: "1234" });
      expect(res.status).toBe(201);
    });
    it("[4] responds with the correct user after registering", async () => {
      const res = await request(server)
        .post("/api/auth/register")
        .send({ username: "bob", password: "1234" });
      expect(res.body).toMatchObject({
        username: "bob",
      });
      expect(res.body.password).not.toBeDefined();
    });
    it("[5] responds with the right status and message on missing password", async () => {
      const res = await request(server)
        .post("/api/auth/register")
        .send({ username: "roger" });
      expect(res.body.message).toMatch(/username and password required/);
      expect(res.status).toBe(422);
    });
    it("[6] responds with the right status and message on missing username", async () => {
      const res = await request(server)
        .post("/api/auth/register")
        .send({ password: "1234" });
      expect(res.body.message).toMatch(/username and password required/);
      expect(res.status).toBe(422);
    });
    it("[7] responds with the right status and message if password is not a string", async () => {
      const res = await request(server)
        .post("/api/auth/register")
        .send({ username: "roger", password: 1234 });
      expect(res.body.message).toMatch(/password must be a string/);
      expect(res.status).toBe(422);
    });
    it("[8] responds with the right status and message if username is taken", async () => {
      await request(server)
        .post("/api/auth/register")
        .send({ username: "roger", password: "1234" });
      const res = await request(server)
        .post("/api/auth/register")
        .send({ username: "roger", password: "5678" });
      expect(res.body.message).toMatch(/username taken/);
      expect(res.status).toBe(422);
    });
  });
  describe("[POST] /api/auth/login", () => {
    it("[1] responds with the right message when logging in with valid credentials", async () => {
      const res = await request(server)
        .post("/api/auth/login")
        .send({ username: "roger", password: "1234" });
      expect(res.body.message).toMatch(/welcome, roger/i);
    });
    it("[2] responds with the right status and message when missing username", async () => {
      const res = await request(server)
        .post("/api/auth/login")
        .send({ password: "1234" });
      expect(res.body.message).toMatch(/username and password required/i);
      expect(res.status).toBe(422);
    });
    it("[3] responds with the right status and message when missing password", async () => {
      const res = await request(server)
        .post("/api/auth/login")
        .send({ username: "roger" });
      expect(res.body.message).toMatch(/username and password required/i);
      expect(res.status).toBe(422);
    });
    it("[4] responds with the right status and message when username is invalid", async () => {
      const res = await request(server)
        .post("/api/auth/login")
        .send({ username: "rogers", password: "1234" });
      expect(res.body.message).toMatch(/invalid credentials/i);
      expect(res.status).toBe(401);
    });
    it("[5] responds with the right status and message when password is invalid", async () => {
      const res = await request(server)
        .post("/api/auth/login")
        .send({ username: "roger", password: "5678" });
      expect(res.body.message).toMatch(/invalid credentials/i);
      expect(res.status).toBe(401);
    });
    it("[6] responds with a properly formed token {subject, username, exp, iat}", async () => {
      let res = await request(server)
        .post("/api/auth/login")
        .send({ username: "roger", password: "1234" });
      let decoded = jwtDecode(res.body.token);
      expect(decoded).toHaveProperty("iat");
      expect(decoded).toHaveProperty("exp");
      expect(decoded).toMatchObject({ subject: 1, username: "roger" });
    });
  });
  describe("[GET] /api/jokes", () => {
    it("[1] requests without a token are rejected with right status and message", async () => {
      const res = await request(server).get("/api/jokes");
      expect(res.body.message).toMatch(/token required/i);
    });
    it("[2] requests with invalid token are rejected with right status and message", async () => {
      const res = await request(server)
        .get("/api/jokes")
        .set("Authorization", "qwerty");
      expect(res.body.message).toMatch(/token invalid/i);
    });
    it("[3] requests with valid token return a list of jokes", async () => {
      const loginRes = await request(server)
        .post("/api/auth/login")
        .send({ username: "roger", password: "1234" });
      const usersRes = await request(server)
        .get("/api/jokes")
        .set("Authorization", loginRes.body.token);
      expect(usersRes.body).toHaveLength(3);
    });
  });
});
