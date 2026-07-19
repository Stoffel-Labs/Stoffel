import { createServer } from "node:http";
import { createReadStream, mkdirSync, writeFileSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { generateKeyPairSync, sign } from "node:crypto";
import { spawn } from "node:child_process";
import { createConnection } from "node:net";
import { chromium } from "playwright";

const fixture = new URL(".", import.meta.url).pathname;
const artifacts = join(fixture, "artifacts");
mkdirSync(artifacts, { recursive: true });
const origin = "http://127.0.0.1:4173";
const sessionId = "one-browser-real-services";
const processes = [];
let resultResolve;
const resultPromise = new Promise((resolve) => { resultResolve = resolve; });
let servicesPromise;

const required = ["RUN_COORD", "STOFFEL_RUN", "BYTECODE", "CERT_DIR", "PROGRAM_HASH"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`missing ${name}`);
}

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
const verifierKey = publicKeyDer.subarray(publicKeyDer.length - 32).toString("base64url");
const certs = Array.from({ length: 5 }, (_, i) => join(process.env.CERT_DIR, `node-${i}.cert.der`));
const keys = Array.from({ length: 5 }, (_, i) => join(process.env.CERT_DIR, `node-${i}.key.der`));

const serviceEnv = {
  ...process.env,
  STOFFEL_AUTH_TOKEN: "one-browser-local-auth-token",
  STOFFEL_BROWSER_RPC_ENABLED: "1",
  STOFFEL_BROWSER_RPC_ALLOWED_ORIGIN: origin,
  STOFFEL_BROWSER_RPC_COORDINATOR_PORT: "19000",
  STOFFEL_BROWSER_RPC_NODE_PORT_OFFSET: "10000",
  STOFFEL_BROWSER_RPC_TLS_CERT_PATH: certs[0],
  STOFFEL_BROWSER_RPC_TLS_KEY_PATH: keys[0],
  STOFFEL_BROWSER_RPC_VERIFYING_KEY: verifierKey,
  STOFFEL_BROWSER_RPC_ISSUER: "hidden-edge-local",
  STOFFEL_BROWSER_RPC_AUDIENCE: "stoffel-one-browser",
  RUST_LOG: "info",
};

function start(name, command, args) {
  const child = spawn(command, args, { env: serviceEnv, stdio: ["ignore", "pipe", "pipe"] });
  const chunks = [];
  const capture = (data) => chunks.push(data);
  child.stdout.on("data", capture);
  child.stderr.on("data", capture);
  child.on("exit", (code, signal) => {
    writeFileSync(join(artifacts, `${name}.log`), Buffer.concat(chunks));
    if (code && code !== 0) console.error(`${name} exited ${code} (${signal || "no signal"})`);
  });
  processes.push(child);
  return child;
}

function waitPort(port, timeoutMs = 120000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const socket = createConnection({ host: "127.0.0.1", port });
      socket.once("connect", () => { socket.destroy(); resolve(); });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() >= deadline) reject(new Error(`port ${port} did not become ready`));
        else setTimeout(attempt, 250);
      });
    };
    attempt();
  });
}

async function startServices(identityPublicKey) {
  const ids = certs.join(",");
  start("coordinator", process.env.RUN_COORD, [
    "--hash", process.env.PROGRAM_HASH,
    "--initial-mpc-nodes", ids,
    "--server-cert", certs[0],
    "--server-key", keys[0],
    "--n", "5",
    "--t", "1",
    "--program", process.env.BYTECODE,
    "--browser-client-bindings", `0=${identityPublicKey}`,
    "--addr", "127.0.0.1",
  ]);
  await Promise.all([waitPort(31415), waitPort(19000)]);

  const common = [
    process.env.BYTECODE,
    "main",
    "--n-parties", "5",
    "--threshold", "1",
    "--mpc-backend", "honeybadger",
    "--wait-for-clients", "1",
    "--client-input-count", "4",
    "--off-chain-coord", "127.0.0.1:31415",
    "--expected-browser-clients", identityPublicKey,
    "--network-retry-secs", "120",
  ];
  for (let i = 0; i < 5; i += 1) {
    const args = [...common];
    if (i === 0) args.push("--leader", "--bind", "127.0.0.1:9000");
    else args.push("--party-id", String(i), "--bootstrap", "127.0.0.1:9000", "--bind", `127.0.0.1:${9000 + i}`);
    args.push("--rpc-bind", `127.0.0.1:${10000 + i}`, "--cert", certs[i], "--key", keys[i]);
    start(`party-${i}`, process.env.STOFFEL_RUN, args);
  }
  await Promise.all(Array.from({ length: 5 }, (_, i) => waitPort(20000 + i, 180000)));
}

function capability(identityPublicKey) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    version: 1,
    issuer: "hidden-edge-local",
    audience: "stoffel-one-browser",
    room_id: "one-browser-room",
    session_id: sessionId,
    client_slot: 0,
    input_start_index: 0,
    input_count: 4,
    can_obtain_output: true,
    browser_hpke_public_key: identityPublicKey,
    allowed_origin: origin,
    issued_at: now,
    expires_at: now + 600,
    nonce: `one-browser-${Date.now()}`,
  };
  const payload = Buffer.from(JSON.stringify(claims));
  const signature = sign(null, payload, privateKey).toString("base64url");
  return `${payload.toString("base64url")}.${signature}`;
}

const mime = new Map([[".html", "text/html"], [".js", "text/javascript"], [".wasm", "application/wasm"], [".json", "application/json"]]);
const server = createServer(async (request, response) => {
  try {
    if (request.method === "POST" && request.url === "/bootstrap") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      servicesPromise ||= startServices(body.identityPublicKey);
      await servicesPromise;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ capability: capability(body.identityPublicKey) }));
      return;
    }
    if (request.method === "POST" && request.url === "/result") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const proof = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const storedProof = { ...proof, identityPublicKey: "[REDACTED]" };
      writeFileSync(join(artifacts, "proof.json"), `${JSON.stringify(storedProof, null, 2)}\n`);
      resultResolve(proof);
      response.writeHead(204).end();
      return;
    }
    const requested = request.url === "/" ? "index.html" : request.url.slice(1);
    const file = normalize(join(fixture, requested));
    if (!file.startsWith(fixture)) throw new Error("invalid path");
    response.writeHead(200, { "content-type": mime.get(extname(file)) || "application/octet-stream", "cache-control": "no-store" });
    createReadStream(file).pipe(response);
  } catch (error) {
    response.writeHead(500, { "content-type": "text/plain" });
    response.end(String(error?.stack || error));
  }
});

let browser;
try {
  await new Promise((resolve) => server.listen(4173, "127.0.0.1", resolve));
  browser = await chromium.launch({ headless: true, args: ["--ignore-certificate-errors", "--allow-insecure-localhost"] });
  const page = await browser.newPage();
  page.on("console", (message) => console.log(`browser:${message.type()}: ${message.text()}`));
  page.on("pageerror", (error) => console.error(`browser:error: ${error.message}`));
  await page.goto(origin, { waitUntil: "load" });
  const proof = await Promise.race([
    resultPromise,
    new Promise((_, reject) => setTimeout(() => reject(new Error("browser proof timed out")), 240000)),
  ]);
  if (proof.error) throw new Error(proof.error);
  if (!proof.directTransport || !proof.transportConnected || proof.applicationServerPrivatePayloads !== 0 || proof.receipt?.inputCount !== 4 || proof.receipt?.state !== "submitted") {
    throw new Error(`invalid proof: ${JSON.stringify(proof)}`);
  }
  console.log(JSON.stringify({ ...proof, identityPublicKey: "[REDACTED]" }, null, 2));
} finally {
  if (browser) await browser.close();
  server.close();
  for (const child of processes.reverse()) child.kill("SIGTERM");
  await new Promise((resolve) => setTimeout(resolve, 1000));
  for (const child of processes) if (!child.killed) child.kill("SIGKILL");
}
process.exit(0);
