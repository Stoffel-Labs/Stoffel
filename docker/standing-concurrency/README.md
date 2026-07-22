# Standing-node Docker acceptance

These tests run five long-lived party containers on one production-shaped
mesh. Each process remains ready until Compose sends SIGTERM; execution IDs are
multiplexed over that mesh rather than creating a mesh or node per program.

```bash
STOFFEL_COORDINATOR_CONTEXT=/absolute/path/to/stoffel-mpc-coordinator \
STOFFEL_NETWORK_CONTEXT=/absolute/path/to/stoffel-networking \
docker/test-standing-concurrency.sh

STOFFEL_COORDINATOR_CONTEXT=/absolute/path/to/stoffel-mpc-coordinator \
STOFFEL_NETWORK_CONTEXT=/absolute/path/to/stoffel-networking \
docker/test-standing-adversarial.sh
```

Both source paths must be local Git checkouts. The tests always rebuild the
standing image from the current VM, coordinator, and networking worktrees and
record their revisions and dirty state under the temporary state directory.
The host needs Docker Compose, Git, and Python 3; the driver has no third-party
Python dependencies.
Set `STOFFEL_KEEP_STANDING_STATE=1` to retain that directory. Useful timeout
overrides are `WAIT_TIMEOUT_SECS`, `COORDINATION_TIMEOUT_SECS`, and
`PROTOCOL_TIMEOUT_SECS`.

## Concurrency campaign

One wave admits and starts six executions together:

| Coverage | Cases |
|---|---|
| Same program, same inputs | two HoneyBadger single-client runs with input `7` |
| Same program, different inputs | another run of that artifact with input `4` |
| Multiple programs | single-, multi-, and split-client artifacts |
| Multiple backends | HoneyBadger and AVSS |
| Multiple client inputs/outputs | two clients each submit two values and receive distinct two-value results |
| Split client roles | client 0 is input-only; client 1 is output-only |

The driver checks client outputs, execution-scoped destructive preprocessing,
cooperative/online yielding, overlapping execution intervals on all parties,
and unchanged node PIDs. A client-free long/short CPU pair then proves that the
VM yields runnable instruction-heavy work: both intervals overlap and the
short sibling completes first.

The nodes are next SIGKILLed and restarted with both the control journal and
all preprocessing volumes retained. They reject a retired execution ID, resume at
the next command sequence, and run nine concurrent executions of the same
program with different inputs. Those reservations cross the reservoir low
watermark; every party must refill before another concurrent pair runs on the
same processes. Finally, only party 2's preprocessing volume is deleted; all
five parties must choose rebuild and complete a fresh execution. This directly
covers the retained-state hang, elastic refill, and asymmetric-store failure
modes without rerunning the entire matrix for every restart.

## Adversarial campaign

The fault campaign keeps the same five node processes alive while it verifies:

- missing or slot-mismatched party certificate rosters fail before mesh setup;
- malformed and oversized control commands are contained, cross-party
  admission mismatches fail before material allocation, and malformed QUIC
  datagrams do not kill or reconfigure nodes;
- a valid but unadmitted client certificate is rejected by every party;
- a delayed party can rejoin both HoneyBadger and AVSS preparation;
- an execution stalled on an absent client does not block a runnable sibling,
  and cancellation reclaims the stalled execution;
- two concurrent, round-heavy executions and their clients complete on the
  healthy `t=1` quorum while one party is frozen online;
- removing two parties causes bounded, fail-closed preparation; and
- reconnecting those parties permits a fresh execution on the original PIDs.

Docker lifecycle and raw datagrams cannot emulate an authenticated Byzantine
party that forges or equivocates valid MPC payloads. Those cases belong in the
transport/protocol tests or a purpose-built malicious peer; this campaign
validates the production process, certificate, timeout, reconnect, and
execution-isolation boundaries.

## Driver contract

Programs are immutable, content-addressed `.stflb` files. The driver publishes
contiguous version-1 `prepare` commands atomically into each party's private
control directory, waits for immutable events, and binds each client to one full
256-bit execution ID. Private keys are mounted as per-service Compose secrets;
the image contains only public certificate rosters.

A `prepare` admission names the execution, program, entry point, and one exact
certificate-to-manifest-slot binding per client:

```json
{
  "execution_id": "<64 lowercase hex characters>",
  "program_id": "<content digest>",
  "entry": "main",
  "clients": [
    {"certificate": "cert0.crt", "manifest_slot": 0}
  ]
}
```

The program manifest is the sole source of the MPC backend, curve, and client
input shape. The matrix keeps backend and curve as fixture metadata only so the
driver can select an artifact and launch a compatible test client; they are not
fields in the standing admission.
