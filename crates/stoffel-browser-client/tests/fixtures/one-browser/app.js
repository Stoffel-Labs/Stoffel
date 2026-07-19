import init, {
  BrowserParticipantClient,
  browserRuntimeAvailable,
} from "./pkg/stoffel_browser_client.js";

const status = document.querySelector("#status");
const report = (value) => {
  status.textContent = JSON.stringify(value, null, 2);
};

const config = {
  participantId: "one-browser-participant",
  sessionId: "one-browser-real-services",
  clientSlot: 0,
  coordinator: { role: "coordinator", url: "wss://127.0.0.1:19000" },
  nodes: Array.from({ length: 5 }, (_, index) => ({
    role: "node",
    url: `wss://127.0.0.1:${20000 + index}`,
  })),
  requestTimeoutMs: 120000,
};

const openVault = () => new Promise((resolve, reject) => {
  const request = indexedDB.open("stoffel-browser-client-one-browser", 1);
  request.onupgradeneeded = () => request.result.createObjectStore("identity");
  request.onerror = () => reject(request.error);
  request.onsuccess = () => resolve(request.result);
});

const readIdentity = async () => {
  const database = await openVault();
  try {
    return await new Promise((resolve, reject) => {
      const request = database.transaction("identity", "readonly")
        .objectStore("identity").get("participant");
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
    });
  } finally {
    database.close();
  }
};

const writeIdentity = async (identity) => {
  const database = await openVault();
  try {
    await new Promise((resolve, reject) => {
      const transaction = database.transaction("identity", "readwrite");
      transaction.objectStore("identity").put(identity, "participant");
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error);
    });
  } finally {
    database.close();
  }
};

try {
  await init();
  if (!browserRuntimeAvailable()) throw new Error("WASM did not detect a browser runtime");

  const persisted = await readIdentity();
  if (!persisted) {
    const created = await BrowserParticipantClient.initialize(config);
    if (created.persistentIdentity.privateKey.extractable) {
      throw new Error("persistent identity private key is extractable");
    }
    await writeIdentity(created.persistentIdentity);
    location.reload();
  } else {
    const client = await BrowserParticipantClient.initializeWithIdentity(config, persisted);
    if (client.identityPublicKey !== persisted.publicKey) {
      throw new Error("restored identity public key changed");
    }

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const aad = encoder.encode("schema-v1:one-browser-participant:room-1");
    const plaintext = encoder.encode(JSON.stringify({ roomId: "room-1", draft: [0, 80, 2, 1] }));
    const envelope = client.sealUserState(plaintext, aad);
    const opened = await client.openUserState(envelope, aad);
    if (decoder.decode(opened) !== decoder.decode(plaintext)) {
      throw new Error("HPKE user-state round trip changed plaintext");
    }
    const tampered = structuredClone(envelope);
    tampered.ciphertext = `${tampered.ciphertext.slice(0, -1)}${tampered.ciphertext.endsWith("A") ? "B" : "A"}`;
    let tamperRejected = false;
    try {
      await client.openUserState(tampered, aad);
    } catch {
      tamperRejected = true;
    }
    if (!tamperRejected) throw new Error("tampered HPKE state was accepted");

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
      persistentIdentityRestored: true,
      privateKeyExtractable: persisted.privateKey.extractable,
      hpkeStateRoundTrip: true,
      hpkeTamperRejected: tamperRejected,
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
  }
} catch (error) {
  const failure = { gate: "one-browser", error: String(error?.stack || error) };
  report(failure);
  await fetch("/result", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(failure),
  }).catch(() => {});
}
