import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

// Import the app — by this point env vars and DB are ready from setup.ts
const { default: app } = await import("../index.js");

const TEST_USER = "testuser_truquini";
const TEST_PASS = "StrongPass123!";

let cookie = "";

const TEST_KDF = JSON.stringify({
  version: 2,
  name: "PBKDF2",
  hash: "SHA-256",
  iterations: 600000,
});

describe("Auth API", () => {
  it("POST /api/auth/register — creates a user", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ username: TEST_USER, password: TEST_PASS })
      .expect("Content-Type", /json/)
      .expect(201);

    expect(res.body).toHaveProperty("message", "Usuario creado exitosamente");
  });

  it("POST /api/auth/register — rejects duplicate", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ username: TEST_USER, password: TEST_PASS })
      .expect(409);

    expect(res.body).toHaveProperty("error", "El usuario ya existe");
  });

  it("POST /api/auth/register — rejects short password", async () => {
    const res = await request(app)
      .post("/api/auth/register")
      .send({ username: "newuser_test", password: "123" })
      .expect(400);

    expect(res.body).toHaveProperty(
      "error",
      "La contraseña debe tener al menos 8 caracteres"
    );
  });

  it("POST /api/auth/login — succeeds with valid credentials", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ username: TEST_USER, password: TEST_PASS })
      .expect(200);

    expect(res.body).toHaveProperty("username", TEST_USER);
    // Capture Set-Cookie for subsequent tests
    const setCookie = res.headers["set-cookie"];
    cookie = Array.isArray(setCookie) ? setCookie[0] : String(setCookie);
    expect(cookie).toBeTruthy();
  });

  it("POST /api/auth/login — fails with wrong password", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ username: TEST_USER, password: "WrongPassword!" })
      .expect(401);

    expect(res.body).toHaveProperty(
      "error",
      "Usuario o contraseña incorrectos"
    );
  });

  it("POST /api/auth/login — fails with nonexistent user", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ username: "noone_exists", password: "SomePass123!" })
      .expect(401);

    expect(res.body).toHaveProperty(
      "error",
      "Usuario o contraseña incorrectos"
    );
  });

  it("POST /api/auth/login — rejects short username for security", async () => {
    const res = await request(app)
      .post("/api/auth/login")
      .send({ username: "ab", password: "SomePass123!" })
      .expect(400);

    expect(res.body).toHaveProperty(
      "error",
      "Usuario o contraseña incorrectos"
    );
  });

  it("GET /api/auth/me — returns username with valid cookie", async () => {
    const res = await request(app)
      .get("/api/auth/me")
      .set("Cookie", cookie)
      .expect(200);

    expect(res.body).toHaveProperty("username", TEST_USER);
  });

  it("GET /api/auth/me — fails without cookie", async () => {
    const res = await request(app).get("/api/auth/me").expect(401);

    expect(res.body).toHaveProperty("error");
    expect(res.body.error).toContain("No autorizado");
  });
});

describe("Vault API", () => {
  it("GET /api/vault — returns 401 without auth", async () => {
    const res = await request(app).get("/api/vault").expect(401);

    expect(res.body).toHaveProperty("error");
    expect(res.body.error).toContain("No autorizado");
  });

  it("GET /api/vault — returns 404 when no vault exists", async () => {
    const res = await request(app)
      .get("/api/vault")
      .set("Cookie", cookie)
      .expect(404);

    expect(res.body).toHaveProperty("error", "No hay bóveda guardada aún");
  });

  it("PUT /api/vault — creates a new blob", async () => {
    const blobPayload = {
      salt: "a".repeat(32),
      iv: "b".repeat(24),
      data: "c".repeat(100),
      kdf: TEST_KDF,
      baseVersion: 0,
    };

    const res = await request(app)
      .put("/api/vault")
      .set("Cookie", cookie)
      .send(blobPayload)
      .expect(200);

    expect(res.body).toHaveProperty("updatedAt");
    expect(res.body).toHaveProperty("version", 1);
  });

  it("PUT /api/vault — updates existing blob", async () => {
    const blobPayload = {
      salt: "d".repeat(32),
      iv: "e".repeat(24),
      data: "f".repeat(200),
      kdf: TEST_KDF,
      baseVersion: 1,
    };

    const res = await request(app)
      .put("/api/vault")
      .set("Cookie", cookie)
      .send(blobPayload)
      .expect(200);

    expect(res.body).toHaveProperty("updatedAt");
    expect(res.body).toHaveProperty("version", 2);
  });

  it("GET /api/vault — returns blob after PUT", async () => {
    const res = await request(app)
      .get("/api/vault")
      .set("Cookie", cookie)
      .expect(200);

    expect(res.body).toHaveProperty("salt");
    expect(res.body).toHaveProperty("iv");
    expect(res.body).toHaveProperty("data");
    expect(res.body).toHaveProperty("kdf", TEST_KDF);
    expect(res.body).toHaveProperty("version");
    expect(res.body.version).toBe(2); // was version 1 after first PUT
  });

  it("PUT /api/vault — rejects a stale baseVersion with 409 and no overwrite", async () => {
    const res = await request(app)
      .put("/api/vault")
      .set("Cookie", cookie)
      .send({
        salt: "g".repeat(32),
        iv: "h".repeat(24),
        data: "i".repeat(300),
        kdf: TEST_KDF,
        baseVersion: 1, // current server version is 2
      })
      .expect(409);

    expect(res.body).toHaveProperty("version", 2);
    expect(res.body.error).toContain("modificada en otra pestaña o dispositivo");

    // La versión y el contenido deben seguir intactos.
    const current = await request(app)
      .get("/api/vault")
      .set("Cookie", cookie)
      .expect(200);

    expect(current.body.version).toBe(2);
    expect(current.body.data).toBe("f".repeat(200));
  });

  it("PUT /api/vault — rejects missing baseVersion", async () => {
    const res = await request(app)
      .put("/api/vault")
      .set("Cookie", cookie)
      .send({
        salt: "a".repeat(32),
        iv: "b".repeat(24),
        data: "c".repeat(100),
        kdf: TEST_KDF,
      })
      .expect(400);

    expect(res.body.error).toContain("baseVersion es requerido");
  });

  it("PUT /api/vault — rejects oversized payload (JSON body > 6MB limit)", async () => {
    const oversizedPayload = {
      salt: "x".repeat(32),
      iv: "y".repeat(24),
      data: "z".repeat(7 * 1024 * 1024), // 7MB > 6MB JSON limit
      kdf: TEST_KDF,
      baseVersion: 2,
    };

    const res = await request(app)
      .put("/api/vault")
      .set("Cookie", cookie)
      .send(oversizedPayload)
      .expect(413);
  });

  it("PUT /api/vault — rejects oversized data field (5MB limit)", async () => {
    // ~5.2MB data field triggers the custom field validation
    const oversizedPayload = {
      salt: "x".repeat(32),
      iv: "y".repeat(24),
      data: "z".repeat(5.2 * 1024 * 1024),
      kdf: TEST_KDF,
      baseVersion: 2,
    };

    const res = await request(app)
      .put("/api/vault")
      .set("Cookie", cookie)
      .send(oversizedPayload)
      .expect(400);

    expect(res.body).toHaveProperty(
      "error",
      "data excede el tamaño máximo (5MB)"
    );
  });

  it("PUT /api/vault — rejects without auth", async () => {
    const res = await request(app)
      .put("/api/vault")
      .send({ salt: "x", iv: "y", data: "z" })
      .expect(401);
  });
});
