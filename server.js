const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");

function loadEnvironmentFile() {
  const envFile = path.resolve(__dirname, ".env");
  try {
    const contents = require("node:fs").readFileSync(envFile, "utf8");
    for (const line of contents.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const separator = trimmed.indexOf("=");
      if (separator < 1) continue;
      const key = trimmed.slice(0, separator).trim();
      let value = trimmed.slice(separator + 1).trim();
      if (
        (value.startsWith("\"") && value.endsWith("\"")) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      if (process.env[key] === undefined) process.env[key] = value;
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

loadEnvironmentFile();

const scrypt = promisify(crypto.scrypt);
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3000);
const DATA_FILE = path.resolve(process.env.EMS_DATA_FILE || path.join(__dirname, "data", "store.json"));
const SESSION_COOKIE = "readyresponse_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 64 * 1024;
const PASSWORD_LENGTH = 64;
const SCRYPT_OPTIONS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const OWNER_CREDENTIALS_FILE = path.resolve(
  process.env.OWNER_CREDENTIALS_FILE || path.join(__dirname, "data", "owner.json"),
);
const PAGE_FILES = {
  "/": "index.html",
  "/login": "login/index.html",
  "/register": "register/index.html",
  "/report": "report/index.html",
  "/owner": "owner/index.html",
  "/app.js": "app.js",
};

let store = { users: [], reports: {} };
let writeQueue = Promise.resolve();
let ownerCredentials = [];
const sessions = new Map();
const failedLogins = new Map();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function normalizeOwnerIdentifier(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function send(res, status, body, contentType = "text/plain; charset=utf-8", extraHeaders = {}) {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    ...extraHeaders,
  });
  res.end(body);
}

function sendJson(res, status, value, extraHeaders = {}) {
  send(res, status, JSON.stringify(value), "application/json; charset=utf-8", extraHeaders);
}

function cookieValue(req, name) {
  const cookies = (req.headers.cookie || "").split(";");
  for (const cookie of cookies) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name) return value.join("=");
  }
  return "";
}

function sessionFor(req) {
  const token = cookieValue(req, SESSION_COOKIE);
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  if (session.role === "user") {
    const user = store.users.find((item) => item.id === session.userId);
    if (!user || user.disabled) {
      sessions.delete(token);
      return null;
    }
    return { ...session, email: user.email };
  }
  return session;
}

function setSessionCookie(res, token, maxAge) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`);
}

function createSession(res, role, userId, email) {
  const token = crypto.randomBytes(32).toString("base64url");
  sessions.set(token, {
    role,
    userId,
    email,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  setSessionCookie(res, token, Math.floor(SESSION_TTL_MS / 1000));
}

function clearSession(req, res) {
  const token = cookieValue(req, SESSION_COOKIE);
  if (token) sessions.delete(token);
  setSessionCookie(res, "", 0);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, "Request is too large.");
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("Expected an object");
    return value;
  } catch {
    throw new HttpError(400, "Invalid JSON request.");
  }
}

function assertSameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return;
  try {
    if (new URL(origin).host !== req.headers.host) throw new HttpError(403, "Cross-origin requests are not allowed.");
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(403, "Invalid request origin.");
  }
}

async function passwordHash(password, salt) {
  return scrypt(password, salt, PASSWORD_LENGTH, SCRYPT_OPTIONS);
}

async function verifyPassword(password, saltHex, hashBase64) {
  const derived = await passwordHash(password, Buffer.from(saltHex, "hex"));
  const expected = Buffer.from(hashBase64, "base64");
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

async function configureOwner() {
  const password = process.env.OWNER_PASSWORD;
  const configuredEmail = normalizeEmail(process.env.OWNER_EMAIL);
  delete process.env.OWNER_PASSWORD;
  delete process.env.OWNER_EMAIL;

  try {
    const saved = JSON.parse(await fs.readFile(OWNER_CREDENTIALS_FILE, "utf8"));
    if (Array.isArray(saved.owners)) {
      ownerCredentials = [];
      for (const owner of saved.owners) {
        if (
          typeof owner.name !== "string" ||
          typeof (owner.email || owner.username) !== "string" ||
          typeof owner.salt !== "string" ||
          typeof owner.passwordHash !== "string" ||
          !/^[a-f0-9]{32}$/i.test(owner.salt) ||
          Buffer.from(owner.passwordHash, "base64").length !== PASSWORD_LENGTH
        ) {
          throw new Error("The owner credentials file has an invalid structure.");
        }
        const identifier = normalizeOwnerIdentifier(owner.email || owner.username);
        if (!identifier) throw new Error("The owner credentials file has an invalid structure.");
        ownerCredentials.push({
          name: owner.name.trim(),
          identifier,
          salt: owner.salt,
          hash: owner.passwordHash,
        });
      }
      if (ownerCredentials.length === 0) throw new Error("The owner credentials file has no owner accounts.");
      return;
    }
    if (
      typeof saved.email !== "string" ||
      typeof saved.salt !== "string" ||
      typeof saved.passwordHash !== "string" ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(saved.email) ||
      !/^[a-f0-9]{32}$/i.test(saved.salt) ||
      Buffer.from(saved.passwordHash, "base64").length !== PASSWORD_LENGTH
    ) {
      throw new Error("The owner credentials file has an invalid structure.");
    }
    ownerCredentials = [{
      name: "Owner",
      identifier: normalizeEmail(saved.email),
      salt: saved.salt,
      hash: saved.passwordHash,
    }];
    return;
  } catch (error) {
    if (error.code !== "ENOENT") throw new Error(`Unable to load ${OWNER_CREDENTIALS_FILE}: ${error.message}`);
  }

  if (!password) return;
  if (!configuredEmail || password.length > 1024 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(configuredEmail)) {
    throw new Error("Owner setup requires a valid OWNER_EMAIL and a password no longer than 1024 characters.");
  }

  const salt = crypto.randomBytes(16);
  const hash = await passwordHash(password, salt);
  const credentials = {
    email: configuredEmail,
    salt: salt.toString("hex"),
    passwordHash: hash.toString("base64"),
  };
  await fs.mkdir(path.dirname(OWNER_CREDENTIALS_FILE), { recursive: true, mode: 0o700 });
  const tempFile = `${OWNER_CREDENTIALS_FILE}.${process.pid}.tmp`;
  await fs.writeFile(tempFile, JSON.stringify(credentials, null, 2), { encoding: "utf8", mode: 0o600 });
  await fs.rename(tempFile, OWNER_CREDENTIALS_FILE);
  ownerCredentials = [{
    name: "Owner",
    identifier: credentials.email,
    salt: credentials.salt,
    hash: credentials.passwordHash,
  }];
}

function allowLoginAttempt(req) {
  const address = req.socket.remoteAddress || "unknown";
  const now = Date.now();
  const previous = failedLogins.get(address);
  if (previous && previous.blockedUntil > now) return false;
  if (failedLogins.size > 500) {
    for (const [key, attempt] of failedLogins) {
      if (attempt.blockedUntil <= now) failedLogins.delete(key);
    }
  }
  return true;
}

function recordFailedLogin(req) {
  const address = req.socket.remoteAddress || "unknown";
  const previous = failedLogins.get(address);
  const attempts = (previous && previous.attempts || 0) + 1;
  failedLogins.set(address, {
    attempts: attempts >= 10 ? 0 : attempts,
    blockedUntil: attempts >= 10 ? Date.now() + 15 * 60 * 1000 : 0,
  });
}

function clearFailedLogins(req) {
  failedLogins.delete(req.socket.remoteAddress || "unknown");
}

async function persistStore() {
  const contents = JSON.stringify(store, null, 2);
  writeQueue = writeQueue.catch(() => {}).then(async () => {
    await fs.mkdir(path.dirname(DATA_FILE), { recursive: true, mode: 0o700 });
    const tempFile = `${DATA_FILE}.${process.pid}.tmp`;
    await fs.writeFile(tempFile, contents, { encoding: "utf8", mode: 0o600 });
    await fs.rename(tempFile, DATA_FILE);
  });
  return writeQueue;
}

async function sendDiscordMessage(channelId, content, embed = null) {
  const token = process.env.DISCORD_BOT_TOKEN;
  if (!token || !channelId) return null;
  const response = await fetch(`https://discord.com/api/v10/channels/${encodeURIComponent(channelId)}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      content,
      ...(embed ? { embeds: [embed] } : {}),
      allowed_mentions: { parse: [] },
    }),
  });
  if (!response.ok) {
    const details = await response.text();
    throw new Error(`Discord message failed (${response.status}): ${details}`);
  }
  return response.json();
}

function reportDiscordEmbed(report, user) {
  const patientName = report.fullName?.trim() || user?.displayName?.trim() || "Unknown patient";
  const fields = [
    ["Date of birth", report.birthDate],
    ["Phone", report.phone],
    ["Blood type", report.bloodType],
    ["Height", report.height],
    ["Weight", report.weight],
    ["Address", report.address],
    ["Primary language", report.language],
    ["Primary care physician", report.physician],
    ["Conditions", report.conditions?.join(", ") || "None listed"],
    ["Condition details", report.conditionNotes],
    ["Medications", report.medications],
    ["Allergies", report.allergies],
    ["Pharmacy", report.pharmacy],
    ["Insurance", report.insurance],
    ["Emergency contact", [report.contactName, report.contactRelationship, report.contactPhone].filter(Boolean).join(" - ")],
    ["Special instructions", report.instructions],
  ].map(([name, value]) => ({
    name,
    value: typeof value === "string" && value.trim() ? value.trim().slice(0, 1024) : "Not provided",
    inline: true,
  }));

  return {
    title: patientName,
    description: "Patient emergency report",
    color: 0xad1822,
    fields: [
      { name: "User", value: patientName, inline: true },
      ...fields,
    ].slice(0, 25),
    footer: {
      text: `Report ID: ${user?.id || "Unknown"}`,
    },
  };
}

async function loadStore() {
  try {
    const raw = await fs.readFile(DATA_FILE, "utf8");
    const loaded = JSON.parse(raw);
    if (!loaded || !Array.isArray(loaded.users) || !loaded.reports || typeof loaded.reports !== "object") {
      throw new Error("The data file has an invalid structure.");
    }
    store = loaded;
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw new Error(`Unable to load ${DATA_FILE}: ${error.message}`);
  }
}

async function servePage(res, file) {
  try {
    const content = await fs.readFile(path.join(__dirname, file));
    const contentType = file.endsWith(".js") ? "text/javascript; charset=utf-8" : "text/html; charset=utf-8";
    send(res, 200, content, contentType);
  } catch (error) {
    if (error.code === "ENOENT") return send(res, 404, "Page not found.");
    throw error;
  }
}

function authenticated(session, role) {
  return session && session.role === role;
}

function sanitizeReport(input) {
  const textFields = [
    "fullName", "birthDate", "phone", "bloodType", "height", "weight", "address",
    "language", "physician", "conditionNotes", "medications", "allergies",
    "pharmacy", "insurance", "contactName", "contactRelationship", "contactPhone", "instructions",
  ];
  const report = {};
  for (const field of textFields) {
    const value = input[field] === undefined ? "" : input[field];
    if (typeof value !== "string" || value.length > 4000) {
      throw new HttpError(400, `Invalid value for ${field}.`);
    }
    report[field] = value.trim();
  }
  const conditions = input.conditions === undefined ? [] : input.conditions;
  if (!Array.isArray(conditions) || conditions.length > 20 || conditions.some((item) => typeof item !== "string" || item.length > 80)) {
    throw new HttpError(400, "Invalid medical conditions.");
  }
  report.conditions = [...new Set(conditions)];
  return report;
}

async function createUserAccount(email, password, displayName = "", lastLoginAt = null) {
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpError(400, "Enter a valid email address.");
  }
  if (typeof password !== "string" || password.length < 12 || password.length > 1024) {
    throw new HttpError(400, "Use a password with at least 12 characters.");
  }
  if (typeof displayName !== "string" || displayName.trim().length > 120) {
    throw new HttpError(400, "Name must be 120 characters or fewer.");
  }
  if (store.users.some((user) => user.email === email)) {
    throw new HttpError(409, "An account with that email already exists.");
  }

  const salt = crypto.randomBytes(16);
  const hash = await passwordHash(password, salt);
  if (store.users.some((user) => user.email === email)) {
    throw new HttpError(409, "An account with that email already exists.");
  }
  const user = {
    id: crypto.randomUUID(),
    email,
    displayName: displayName.trim(),
    passwordSalt: salt.toString("hex"),
    passwordHash: hash.toString("base64"),
    createdAt: new Date().toISOString(),
    lastLoginAt,
    disabled: false,
  };
  store.users.push(user);
  try {
    await persistStore();
  } catch (error) {
    store.users.splice(store.users.indexOf(user), 1);
    throw error;
  }
  return user;
}

async function handleApi(req, res, url) {
  if (req.method !== "GET") assertSameOrigin(req);
  const session = sessionFor(req);

  if (req.method === "GET" && url.pathname === "/api/me") {
    return sendJson(res, 200, session ? { role: session.role, email: session.email } : { role: null });
  }

  if (req.method === "POST" && url.pathname === "/api/register") {
    if (!allowLoginAttempt(req)) throw new HttpError(429, "Too many attempts. Try again later.");
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    const user = await createUserAccount(email, body.password, "", new Date().toISOString());
    clearFailedLogins(req);
    createSession(res, "user", user.id, user.email);
    return sendJson(res, 201, { role: "user", email: user.email });
  }

  if (req.method === "POST" && url.pathname === "/api/login") {
    if (!allowLoginAttempt(req)) throw new HttpError(429, "Too many attempts. Try again later.");
    const body = await readJson(req);
    const email = normalizeEmail(body.email);
    const password = typeof body.password === "string" ? body.password : "";
    const user = store.users.find((item) => item.email === email);
    const salt = user ? Buffer.from(user.passwordSalt, "hex") : Buffer.alloc(16);
    const hash = user ? user.passwordHash : Buffer.alloc(PASSWORD_LENGTH).toString("base64");
    const matches = await verifyPassword(password, salt.toString("hex"), hash);
    if (!user || user.disabled || !matches) {
      recordFailedLogin(req);
      throw new HttpError(401, "Email or password is incorrect.");
    }
    user.lastLoginAt = new Date().toISOString();
    await persistStore();
    clearFailedLogins(req);
    createSession(res, "user", user.id, user.email);
    return sendJson(res, 200, { role: "user", email: user.email });
  }

  if (req.method === "POST" && url.pathname === "/api/owner/login") {
    if (!allowLoginAttempt(req)) throw new HttpError(429, "Too many attempts. Try again later.");
    const body = await readJson(req);
    if (ownerCredentials.length === 0) throw new HttpError(503, "Owner sign-in is not configured on the server.");
    const password = typeof body.password === "string" && body.password.length <= 1024 ? body.password : "";
    const identifier = normalizeOwnerIdentifier(body.email);
    const owner = ownerCredentials.find((item) => item.identifier === identifier);
    const passwordIsValid = owner
      ? await verifyPassword(password, owner.salt, owner.hash)
      : false;
    if (!owner || !passwordIsValid) {
      recordFailedLogin(req);
      throw new HttpError(401, "Owner username or password is incorrect.");
    }
    clearFailedLogins(req);
    createSession(res, "owner", "owner", owner.identifier);
    return sendJson(res, 200, { role: "owner", email: owner.identifier, name: owner.name });
  }

  if (req.method === "POST" && url.pathname === "/api/logout") {
    clearSession(req, res);
    return sendJson(res, 200, { ok: true });
  }

  if (url.pathname === "/api/report" && req.method === "GET") {
    if (!authenticated(session, "user")) throw new HttpError(401, "Please log in to view your report.");
    return sendJson(res, 200, store.reports[session.userId] || {});
  }

  if (url.pathname === "/api/report" && req.method === "POST") {
    if (!authenticated(session, "user")) throw new HttpError(401, "Please log in to save your report.");
    const report = sanitizeReport(await readJson(req));
    report.updatedAt = new Date().toISOString();
    store.reports[session.userId] = report;
    await persistStore();
    try {
      const user = store.users.find((item) => item.id === session.userId);
      const message = await sendDiscordMessage(
        process.env.DISCORD_ACCEPTED_CHANNEL_ID,
        null,
        reportDiscordEmbed(report, user),
      );
      return sendJson(res, 200, { ok: true, updatedAt: report.updatedAt, discordDelivered: Boolean(message) });
    } catch (error) {
      console.error(`Discord report delivery failed: ${error.message}`);
      return sendJson(res, 200, {
        ok: true,
        updatedAt: report.updatedAt,
        discordDelivered: false,
        warning: "Your report was saved, but it could not be sent to Discord.",
      });
    }
  }

  if (req.method === "GET" && url.pathname === "/api/owner/dashboard") {
    if (!authenticated(session, "owner")) throw new HttpError(401, "Owner sign-in required.");
    const users = store.users.map(({ id, email, displayName, createdAt, disabled }) => ({ id, email, displayName, createdAt, disabled }));
    const reports = Object.entries(store.reports).flatMap(([userId, report]) => {
      const user = store.users.find((item) => item.id === userId);
      return user ? [{ userId, email: user.email, report }] : [];
    });
    return sendJson(res, 200, { users, reports });
  }

  if (req.method === "POST" && url.pathname === "/api/owner/users") {
    if (!authenticated(session, "owner")) throw new HttpError(401, "Owner sign-in required.");
    const body = await readJson(req);
    if (typeof body.name !== "string" || !body.name.trim()) throw new HttpError(400, "Enter the person's name.");
    const user = await createUserAccount(normalizeEmail(body.email), body.password, body.name);
    return sendJson(res, 201, { id: user.id, email: user.email, displayName: user.displayName });
  }

  const userAction = url.pathname.match(/^\/api\/owner\/users\/([a-f0-9-]+)$/i);
  if (userAction && req.method === "PATCH") {
    if (!authenticated(session, "owner")) throw new HttpError(401, "Owner sign-in required.");
    const body = await readJson(req);
    if (typeof body.disabled !== "boolean") throw new HttpError(400, "Invalid account status.");
    const user = store.users.find((item) => item.id === userAction[1]);
    if (!user) throw new HttpError(404, "User not found.");
    user.disabled = body.disabled;
    await persistStore();
    return sendJson(res, 200, { ok: true });
  }

  if (userAction && req.method === "DELETE") {
    if (!authenticated(session, "owner")) throw new HttpError(401, "Owner sign-in required.");
    const index = store.users.findIndex((item) => item.id === userAction[1]);
    if (index < 0) throw new HttpError(404, "User not found.");
    store.users.splice(index, 1);
    delete store.reports[userAction[1]];
    await persistStore();
    return sendJson(res, 200, { ok: true });
  }

  throw new HttpError(404, "API route not found.");
}

const server = http.createServer(async (req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'");

  try {
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) return await handleApi(req, res, url);

    if (req.method !== "GET") throw new HttpError(405, "Method not allowed.");
    const route = url.pathname === "/" ? "/" : url.pathname.replace(/\/+$/, "");
    if (route === "/report") {
      const session = sessionFor(req);
      if (!authenticated(session, "user")) {
        res.writeHead(302, { Location: "/login?next=/report", "Cache-Control": "no-store" });
        return res.end();
      }
    }
    const file = PAGE_FILES[route];
    if (!file) throw new HttpError(404, "Page not found.");
    await servePage(res, file);
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    if (status >= 500) console.error(error);
    if (res.headersSent) return res.end();
    if (req.url.startsWith("/api/")) {
      return sendJson(res, status, { error: status === 500 ? "An unexpected server error occurred." : error.message });
    }
    return send(res, status, status === 500 ? "An unexpected server error occurred." : error.message);
  }
});

Promise.all([loadStore(), configureOwner()]).then(() => {
  server.listen(PORT, HOST, () => {
    console.log(`ReadyResponse running at http://${HOST}:${PORT}`);
    console.log(`Data file: ${DATA_FILE}`);
  });
}).catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
