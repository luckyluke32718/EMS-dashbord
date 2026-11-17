const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");

const root = path.join(__dirname, "..");

async function unusedPort() {
  const probe = net.createServer();
  await new Promise((resolve, reject) => {
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", resolve);
  });
  const { port } = probe.address();
  await new Promise((resolve, reject) => probe.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function startServer(port, dataFile, ownerFile) {
  let output = "";
  const child = spawn(process.execPath, [path.join(root, "server.js")], {
    cwd: root,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      EMS_DATA_FILE: dataFile,
      OWNER_CREDENTIALS_FILE: ownerFile,
      OWNER_EMAIL: "owner@example.test",
      OWNER_PASSWORD: "owner-test-password-that-is-long",
      DISCORD_BOT_TOKEN: "",
      DISCORD_ACCEPTED_CHANNEL_ID: "",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  const baseUrl = `http://127.0.0.1:${port}`;

  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Server exited during startup: ${output}`);
    try {
      const response = await fetch(baseUrl);
      if (response.ok) return { child, baseUrl, output: () => output };
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  child.kill();
  throw new Error(`Server did not start: ${output}`);
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  child.kill();
  await new Promise((resolve) => child.once("exit", resolve));
}

async function request(baseUrl, route, { method = "GET", cookie, body } = {}) {
  const headers = {};
  if (cookie) headers.Cookie = cookie;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual",
  });
  const data = await response.json().catch(() => null);
  return { response, data };
}

function sessionCookie(response) {
  const cookie = response.headers.get("set-cookie");
  assert.ok(cookie, "expected the server to issue a session cookie");
  return cookie.split(";", 1)[0];
}

test("login and registration return to home before opening the report", async () => {
  const app = await fs.readFile(path.join(root, "app.js"), "utf8");
  const home = await fs.readFile(path.join(root, "index.html"), "utf8");
  const report = await fs.readFile(path.join(root, "report", "index.html"), "utf8");
  const server = await fs.readFile(path.join(root, "server.js"), "utf8");
  const envExample = await fs.readFile(path.join(root, ".env.example"), "utf8");
  assert.match(app, /window\.location\.assign\("\/"\)/);
  assert.doesNotMatch(app, /login[\s\S]*window\.location\.assign\("\/report"\)/);
  assert.doesNotMatch(app, /register[\s\S]*window\.location\.assign\("\/report"\)/);
  assert.match(home, /href="\/report\?new=1"[^>]*>Create your patient report/);
  assert.match(home, /href="\/report\?new=1">Create report/);
  assert.match(report, /id="new-report-link" href="#report"/);
  assert.match(app, /new URLSearchParams\(window\.location\.search\)\.get\("new"\) === "1"/);
  assert.match(home, /id="home-auth-button">Log in<\/button>/);
  assert.match(home, /src="\/app\.js"/);
  assert.doesNotMatch(report, />How it works</);
  assert.doesNotMatch(report, />Your information</);
  assert.match(report, /<title>ReadyResponse — Patient Report<\/title>/);
  assert.match(report, /<h3 id="report-title">Patient Emergency Medical Report<\/h3>/);
  assert.match(report, />Patient information</);
  assert.match(report, /id="clear-form" type="reset">New report/);
  assert.match(app, /await requestJson\("\/api\/report", \{ method: "POST"[\s\S]*?window\.location\.assign\("\/"\)/);
  assert.match(app, /requestJson\("\/api\/me"\)[\s\S]*?homeAuthButton\.textContent = "Log out"/);
  assert.match(app, /querySelectorAll\("\.login-prompt"\)/);
  assert.match(server, /DISCORD_ACCEPTED_CHANNEL_ID/);
  assert.match(server, /embeds: \[embed\]/);
  assert.match(server, /name: "User", value: patientName/);
  assert.match(server, /function reportDiscordEmbed/);
  assert.doesNotMatch(server, /DISCORD_REVIEW_CHANNEL_ID|reviewStatus = "pending"|\/approve|\/reject/);
  assert.doesNotMatch(app, /Review status:|textContent = "Approve"|textContent = "Reject"/);
  assert.match(envExample, /DISCORD_BOT_TOKEN=/);
  assert.match(envExample, /DISCORD_ACCEPTED_CHANNEL_ID=/);
});

test("supports multiple owner sign-ins", { timeout: 30000 }, async (t) => {
  const crypto = require("node:crypto");
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "readyresponse-owner-test-"));
  const dataFile = path.join(directory, "store.json");
  const ownerFile = path.join(directory, "owner.json");
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync("second-owner-password", salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const firstSalt = crypto.randomBytes(16);
  const firstHash = crypto.scryptSync("owner-password", firstSalt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  await fs.writeFile(ownerFile, JSON.stringify({
    owners: [
      { name: "Owner", email: "owner@example.test", salt: firstSalt.toString("hex"), passwordHash: firstHash.toString("base64") },
      { name: "Brady", username: "Brady", salt: salt.toString("hex"), passwordHash: hash.toString("base64") },
    ],
  }));
  const port = await unusedPort();
  const running = await startServer(port, dataFile, ownerFile);
  t.after(async () => {
    await stopServer(running.child);
    await fs.rm(directory, { recursive: true, force: true });
  });

  const result = await request(running.baseUrl, "/api/owner/login", {
    method: "POST",
    body: { email: "Brady", password: "second-owner-password" },
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.name, "Brady");
  assert.equal(result.data.email, "brady");
});

test("requires login, persists hashed accounts and reports, and limits owner access", { timeout: 30000 }, async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "readyresponse-test-"));
  const dataFile = path.join(directory, "store.json");
  const ownerFile = path.join(directory, "owner.json");
  const port = await unusedPort();
  let running = await startServer(port, dataFile, ownerFile);
  t.after(async () => {
    if (running) await stopServer(running.child);
    await fs.rm(directory, { recursive: true, force: true });
  });

  let result = await request(running.baseUrl, "/report");
  assert.equal(result.response.status, 302);
  assert.equal(result.response.headers.get("location"), "/login?next=/report");

  result = await request(running.baseUrl, "/api/report", { method: "POST", body: { fullName: "Not signed in" } });
  assert.equal(result.response.status, 401);

  result = await request(running.baseUrl, "/api/owner/dashboard");
  assert.equal(result.response.status, 401);
  result = await request(running.baseUrl, "/api/owner/users", {
    method: "POST",
    body: { name: "Added Person", email: "added@example.test", password: "admin-created-password-12" },
  });
  assert.equal(result.response.status, 401);

  const password = "user-test-password-with-12-plus";
  result = await request(running.baseUrl, "/api/register", {
    method: "POST",
    body: { email: "person@example.test", password },
  });
  assert.equal(result.response.status, 201);
  let userCookie = sessionCookie(result.response);
  let saved = JSON.parse(await fs.readFile(dataFile, "utf8"));
  assert.equal(saved.users.length, 1);
  assert.notEqual(saved.users[0].passwordHash, password);
  assert.equal(saved.users[0].passwordHash.length > 40, true);
  assert.equal(JSON.stringify(saved).includes(password), false);
  const ownerCredentials = JSON.parse(await fs.readFile(ownerFile, "utf8"));
  assert.equal(ownerCredentials.email, "owner@example.test");
  assert.equal(ownerCredentials.passwordHash === "owner-test-password-that-is-long", false);
  assert.equal(JSON.stringify(ownerCredentials).includes("owner-test-password-that-is-long"), false);

  result = await request(running.baseUrl, "/api/report", {
    method: "POST",
    cookie: userCookie,
    body: { fullName: "Test User", allergies: "None known", conditions: ["Asthma"] },
  });
  assert.equal(result.response.status, 200);

  result = await request(running.baseUrl, "/api/owner/login", {
    method: "POST",
    body: { email: "owner@example.test", password: "wrong-password" },
  });
  assert.equal(result.response.status, 401);

  result = await request(running.baseUrl, "/api/owner/login", {
    method: "POST",
    body: { email: "owner@example.test", password: "owner-test-password-that-is-long" },
  });
  assert.equal(result.response.status, 200);
  let ownerCookie = sessionCookie(result.response);
  result = await request(running.baseUrl, "/api/owner/dashboard", { cookie: ownerCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.users[0].email, "person@example.test");
  assert.equal(result.data.reports[0].report.fullName, "Test User");

  const addedPassword = "admin-created-password-12";
  result = await request(running.baseUrl, "/api/owner/users", {
    method: "POST",
    cookie: ownerCookie,
    body: { name: "Added Person", email: "added@example.test", password: addedPassword },
  });
  assert.equal(result.response.status, 201);
  const addedUserId = result.data.id;
  saved = JSON.parse(await fs.readFile(dataFile, "utf8"));
  const addedUser = saved.users.find((user) => user.id === addedUserId);
  assert.equal(addedUser.displayName, "Added Person");
  assert.notEqual(addedUser.passwordHash, addedPassword);
  assert.equal(JSON.stringify(addedUser).includes(addedPassword), false);

  result = await request(running.baseUrl, "/api/login", {
    method: "POST",
    body: { email: "added@example.test", password: addedPassword },
  });
  assert.equal(result.response.status, 200, "owner-created accounts can sign in");

  result = await request(running.baseUrl, `/api/owner/users/${saved.users[0].id}`, {
    method: "PATCH",
    cookie: ownerCookie,
    body: { disabled: true },
  });
  assert.equal(result.response.status, 200);
  result = await request(running.baseUrl, "/api/report", { cookie: userCookie });
  assert.equal(result.response.status, 401);

  await stopServer(running.child);
  running = await startServer(port, dataFile, ownerFile);
  result = await request(running.baseUrl, "/api/login", {
    method: "POST",
    body: { email: "person@example.test", password },
  });
  assert.equal(result.response.status, 401, "disabled accounts cannot sign in after a restart");

  result = await request(running.baseUrl, "/api/owner/login", {
    method: "POST",
    body: { email: "owner@example.test", password: "owner-test-password-that-is-long" },
  });
  ownerCookie = sessionCookie(result.response);
  result = await request(running.baseUrl, `/api/owner/users/${saved.users[0].id}`, {
    method: "PATCH",
    cookie: ownerCookie,
    body: { disabled: false },
  });
  assert.equal(result.response.status, 200);

  result = await request(running.baseUrl, "/api/login", {
    method: "POST",
    body: { email: "person@example.test", password },
  });
  assert.equal(result.response.status, 200);
  userCookie = sessionCookie(result.response);
  result = await request(running.baseUrl, "/api/report", { cookie: userCookie });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.fullName, "Test User");

  result = await request(running.baseUrl, `/api/owner/users/${saved.users[0].id}`, {
    method: "DELETE",
    cookie: ownerCookie,
  });
  assert.equal(result.response.status, 200);
  result = await request(running.baseUrl, `/api/owner/users/${addedUserId}`, {
    method: "DELETE",
    cookie: ownerCookie,
  });
  assert.equal(result.response.status, 200);
  saved = JSON.parse(await fs.readFile(dataFile, "utf8"));
  assert.equal(saved.users.length, 0);
  assert.equal(Object.keys(saved.reports).length, 0);
});
