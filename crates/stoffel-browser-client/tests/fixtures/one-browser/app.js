import init, {
  BrowserParticipantClient,
  browserRuntimeAvailable,
} from "./pkg/stoffel_browser_client.js";

const status = document.querySelector("#status");
const report = (value) => {
  status.textContent = JSON.stringify(value, null, 2);
};

try {
  await init();
  if (!browserRuntimeAvailable()) throw new Error("WASM did not detect a browser runtime");

  const endpoints = {
    coordinator: { role: "coordinator", url: "wss://127.0.0.1:19000" },
    nodes: Array.from({ length: 5 }, (_, index) => ({
      role: "node",
      url: `wss://127.0.0.1:${20000 + index}`,
    })),
  };
  const client = BrowserParticipantClient.initialize({
    participantId: "one-browser-participant",
    sessionId: "one-browser-real-services",
    clientSlot: 0,
    coordinator: endpoints.coordinator,
    nodes: endpoints.nodes,
    requestTimeoutMs: 120000,
  });

  const bootstrapResponse = await fetch("/bootstrap", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identityPublicKey: client.identityPublicKey }),
  });
  if (!bootstrapResponse.ok) throw new Error(await bootstrapResponse.text());
  const { capability } = await bootstrapResponse.json();

  const receipt = await client.submitPrivateInputs(capability, [0, 80, 2, 1]);
  const proof = {
    gate: "one-browser",
    runtime: "chromium-wasm",
    directTransport: true,
    applicationServerPrivatePayloads: 0,
    identityPublicKey: client.identityPublicKey,
    transportConnected: client.transportConnected,
    receipt,
  };
  report(proof);
  await fetch("/result", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(proof),
  });
} catch (error) {
  const failure = { gate: "one-browser", error: String(error?.stack || error) };
  report(failure);
  await fetch("/result", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(failure),
  }).catch(() => {});
}
