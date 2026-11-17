const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const readline = require("node:readline");
const { StringDecoder } = require("node:string_decoder");
const { promisify } = require("node:util");

const scrypt = promisify(crypto.scrypt);
const ownerFile = path.resolve(
  process.env.OWNER_CREDENTIALS_FILE || path.join(__dirname, "data", "owner.json"),
);
const PASSWORD_LENGTH = 64;
const SCRYPT_OPTIONS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function ask(prompt) {
  const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => terminal.question(prompt, (answer) => {
    terminal.close();
    resolve(answer.trim());
  }));
}

function askHidden(prompt) {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
    return Promise.reject(new Error("Run this setup command in an interactive terminal so the password can be hidden."));
  }

  return new Promise((resolve, reject) => {
    const input = process.stdin;
    const decoder = new StringDecoder("utf8");
    let value = "";
    let finished = false;

    function finish(error) {
      if (finished) return;
      finished = true;
      input.removeListener("data", onData);
      input.setRawMode(false);
      process.stdout.write("\n");
      if (error) reject(error);
      else resolve(value);
    }

    function onData(buffer) {
      for (const character of decoder.write(buffer)) {
        if (character === "\u0003") return finish(new Error("Owner setup cancelled."));
        if (character === "\r" || character === "\n") return finish();
        if (character === "\u007f" || character === "\b") {
          value = Array.from(value).slice(0, -1).join("");
          continue;
        }
        if (character >= " ") value += character;
      }
    }

    process.stdout.write(prompt);
    input.setRawMode(true);
    input.resume();
    input.on("data", onData);
  });
}

async function main() {
  let existingCredentials = null;
  try {
    existingCredentials = JSON.parse(await fs.readFile(ownerFile, "utf8"));
    const overwrite = await ask("Owner credentials already exist. Replace them? (y/N) ");
    if (overwrite.toLowerCase() !== "y") {
      process.stdout.write("Owner setup cancelled; the existing file was not changed.\n");
      return;
    }
  } catch (error) {
    if (error.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error;
  }

  const email = (await ask("Owner email: ")).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("Enter a valid email address.");

  const password = await askHidden("Owner password (minimum 12 characters): ");
  if (password.length < 12 || password.length > 1024) {
    throw new Error("Use a password between 12 and 1024 characters.");
  }
  const confirmation = await askHidden("Confirm owner password: ");
  if (password !== confirmation) throw new Error("The passwords did not match.");

  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, PASSWORD_LENGTH, SCRYPT_OPTIONS);
  const credentials = {
    email,
    salt: salt.toString("hex"),
    passwordHash: hash.toString("base64"),
  };
  if (existingCredentials && Array.isArray(existingCredentials.owners)) {
    const additionalOwners = existingCredentials.owners.filter((owner) => {
      const identifier = (owner.email || owner.username || "").toLowerCase();
      return identifier !== String(existingCredentials.email || "").toLowerCase();
    }).filter((owner) => (owner.email || owner.username || "").toLowerCase() !== email);
    credentials.owners = [
      { name: "Owner", email, salt: credentials.salt, passwordHash: credentials.passwordHash },
      ...additionalOwners,
    ];
  } else {
    credentials.owners = [
      { name: "Owner", email, salt: credentials.salt, passwordHash: credentials.passwordHash },
    ];
  }

  await fs.mkdir(path.dirname(ownerFile), { recursive: true, mode: 0o700 });
  const tempFile = `${ownerFile}.${process.pid}.tmp`;
  await fs.writeFile(tempFile, JSON.stringify(credentials, null, 2), { encoding: "utf8", mode: 0o600 });
  await fs.rename(tempFile, ownerFile);
  process.stdout.write(`Owner credentials saved to ${ownerFile}\n`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
