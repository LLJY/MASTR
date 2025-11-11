# One-time Host–Token Pairing (Provisioning) Plan

This document explains the goal Lucas is aiming for and outlines the concrete API and UI flow to move the first‑run provisioning from debug prints to the HTTP API + web UI.

---
## Goal in plain terms
- On first boot, the Token (device) and a Host (PC/server) must pair exactly once.
- Today, this pairing uses debug console messages to exchange the Token public key and a "golden hash". The ask is to make this happen via API endpoints and a simple UI wizard so the user can copy/paste the necessary data.
- After pairing, the device should remember the Host and the golden hash, and normal operation begins; subsequent boots should not require pairing again unless reset.

---
## How it works today (CURRENT STATE)

Mechanism today is console/serial driven:
1. Device boots and prints debug messages (via `print_dbg`) exposing: public key, intermediate protocol states, and the "golden hash".
2. A host Python script (or manual copy in a terminal) reads those debug lines, parses out required values.
3. Host responds (over serial protocol frames) with its public key and expected golden hash.
4. Device stores these in RAM (not persisted) and transitions the internal `protocol_state.current_state` to runtime (0x40).

Limitations:
- Manual copy/paste, easy to mis-transcribe.
- No structured validation feedback (just debug prints).
- Values are ephemeral; reboot requires repeating unless separately saved.
- Harder to script remotely (must attach to USB serial).
- No UI representation; provisioning progress opaque unless watching terminal.

Summary: Pairing is implicit, using the existing framed serial protocol and debug lines, not an explicit transactional API.

---
## Target architecture (AFTER CHANGES)

Replace ad‑hoc serial exchange with a REST + UI wizard:
1. Device starts OPEN AP (no password) and advertises provisioning endpoints.
2. Browser hits `/api/provision/state` to see if `provisioned=false`.
3. User opens "Provisioning" page: UI calls `/api/provision/token_info` and displays token public key, optional attestation blob, and (optionally) device-generated golden hash.
4. User (or host software) supplies Host Public Key + Golden Hash via POST `/api/provision/host_submit`.
5. UI shows submitted values for confirmation; user presses "Confirm" -> POST `/api/provision/confirm`.
6. Device persists host key + golden hash + provisioned flag in flash; subsequent `/api/provision/state` returns `provisioned=true` and endpoints are locked.
7. Runtime heartbeat uses `/api/heartbeat` or existing `/api/status`.

Benefits:
- Predictable JSON contracts; easy to automate.
- One-time explicit confirmation step.
- Copy/paste friendly UI (no terminal required).
- Persistence ensures reboot resilience.
- Clear error codes (400, 409) instead of generic debug lines.

---
## Delta: What must change

Area | Current | Required Change
---- | ------- | ---------------
Public key exposure | Printed in debug | Serve via `/api/provision/token_info` JSON
Golden hash exchange | Printed / serial frame | Submit via `/api/provision/host_submit` body
Provisioning state | Implicit in protocol_state | Explicit `/api/provision/state` (provisioned + step)
Confirmation | None (implicit) | `/api/provision/confirm` finalizes & persists
Persistence | RAM only | Flash/EEPROM sector with CRC (host key + hash + flag)
UI | Debug terminal | Web wizard (three steps) in `index.html`
Security gating | N/A | Disable provisioning endpoints after success; require factory reset to re-enable
Attestation | Mixed debug prints | Optional structured field (`attestation.report`, `nonce`)
Errors | Freeform prints | HTTP status + JSON `{ "error": "..." }`

---
## Minimal state machine (new)

State | Description | Transitions
----- | ----------- | ----------
`start` | Device unprovisioned, waiting for user | -> `token_info` on first GET
`token_info` | Token info served | -> `await_host` after host submits data
`await_host` | Host data stored, waiting confirmation | -> `done` on confirm
`done` | Provisioned complete | (locked) unless factory reset

Implementation hint: Store `current_provision_step` in RAM; persist only the final `provisioned` flag and artifacts to flash.

---
## Persistence strategy (flash layout example)

| Offset | Length | Field |
| ------ | ------ | ----- |
| 0x00   | 4      | Magic (0x504B5450 'PKTP') |
| 0x04   | 2      | Version |
| 0x06   | 2      | Host key length |
| 0x08   | N      | Host public key PEM (N bytes) |
| 0x08+N | 2      | Golden hash length |
| ...    | M      | Golden hash bytes (hex or raw) |
| ...    | 1      | Provisioned flag (0x01) |
| ...    | 4      | CRC32 over all preceding fields |

Failure handling:
- On CRC mismatch -> treat as unprovisioned.
- On flash write failure -> return 500 from `/api/provision/confirm`.

---
## Validation rules (to implement)
- Host public key PEM: begins with `-----BEGIN PUBLIC KEY-----`, length within bounds (e.g. 512–2048 bytes).
- Golden hash: hex (even length) or base64; server normalizes to hex internally.
- Reject duplicate provisioning (respond 409 if `provisioned=true`).
- Attestation (if used): nonce length fixed (e.g. 16 bytes), report base64 size check.

---
## Migration plan (step-by-step)
1. Add in-memory scaffolding for new endpoints (no persistence yet) returning mock values.
2. Integrate real token public key extraction (from crypto subsystem) into `/api/provision/token_info`.
3. Implement host submission parsing & validation.
4. Implement flash persistence layer (read/write + CRC) and finalize confirm step.
5. Extend `index.html` with provisioning wizard section; hide existing metrics until provisioned.
6. Gate existing sensitive endpoints (if any) while `!provisioned` (optional).
7. Add factory reset mechanism (e.g., long button press or `/api/provision/reset` with physical presence check).
8. Remove or minimize debug prints of sensitive material (replace with informational logs only).

---
## Risks & Mitigations
Risk | Mitigation
---- | ----------
Power loss during flash write | Write to temp sector then atomic flag set; verify CRC on boot.
Host submits malformed PEM | Strict parser + length limits + 400 response.
Replay / MITM on open AP | Physical proximity assumption + optional attestation challenge.
Accidental re-provision | Require factory reset or signed admin token.

---
## Token vs Host Responsibilities (recap)
Token: Serve provisioning endpoints, validate inputs, persist artifacts, enforce golden hash.
Host: Fetch token info, verify/record, POST host key + golden hash, confirm.

---
## Actors and artifacts
- Token (this device)
  - Token Public Key (from secure element ATECC608A or internal key store)
  - Attestation proof/evidence (optional but recommended)
  - Golden Hash (reference hash of firmware/config or key material agreed upon with Host)
- Host (your PC/app)
  - Host Public Key
  - Expected Golden Hash

Persistent on Token after pairing:
- host_public_key
- golden_hash
- provisioned flag (true)

---
## Trust model (high-level)
- First‑run pairing happens over the Token’s local AP; the user is physically present.
- The Token shows its identity (public key + optional attestation) so the Host can verify.
- The Host provides its public key and the golden hash the Token must enforce at runtime.
- Token stores both and marks itself provisioned.

---
## Proposed API surface (one-time provisioning)
All endpoints are unauthenticated only when not yet provisioned; once provisioned, they are either disabled or require auth.

1) GET `/api/provision/state`
- Purpose: Tell the UI if pairing is needed and what step we’re at.
- Response:
```
{
  "provisioned": false,
  "step": "start" | "token_info" | "await_host" | "done"
}
```

2) GET `/api/provision/token_info`
- Purpose: Provide copy/pasteable Token identity to the user/Host.
- Response:
```
{
  "token_pubkey_pem": "-----BEGIN PUBLIC KEY-----...",
  "attestation": { "nonce": "...", "report": "base64..." },
  "golden_hash": "<hex-or-base64>"
}
```
- Notes: `golden_hash` can be the device’s computed reference hash OR left blank if the Host is the source of truth.

3) POST `/api/provision/host_submit`
- Purpose: Host submits its identity and the expected golden hash.
- Body:
```
{
  "host_pubkey_pem": "-----BEGIN PUBLIC KEY-----...",
  "golden_hash": "<hex-or-base64>"
}
```
- Response: `{ "status": "ok" }` (or errors if invalid format/length)

4) POST `/api/provision/confirm`
- Purpose: Finalize pairing. The Token verifies inputs, persists them, and marks provisioned.
- Body: `{ "confirm": true }`
- Response: `{ "status": "ok", "provisioned": true }`

5) GET `/api/heartbeat` (optional)
- Purpose: UI runtime heartbeat after pairing. Returns a minimal JSON to show live status.
- Response: `{ "ok": true, "uptime_s": <num>, "state": "0x40" }`

---
## UI wizard sketch (one page, three panels)
1) "Token identity" (auto-filled via GET `/api/provision/token_info`)
   - Show Token Public Key (PEM textarea)
   - Show Attestation blob/nonce (optional)
   - Show/Copy the Token’s Golden Hash (if device-generated)
   - Button: Copy to clipboard

2) "Host details"
   - Textarea: Paste Host Public Key (PEM)
   - Input: Golden Hash (hex/base64) – if Host-sourced
   - Button: Submit (POST `/api/provision/host_submit`)

3) "Confirm"
   - Button: Confirm (POST `/api/provision/confirm`)
   - On success, show: "Provisioned ✓" and disable the wizard

Quick safety notes:
- Disable these routes (or require auth) after `provisioned == true`.
- If you support a factory reset, re-enable the routes when reset occurs.

---
## Persistence & storage
- Store `host_pubkey` and `golden_hash` in non-volatile memory (flash/EEPROM or secure element slots, if available).
- Store a `provisioned` flag.
- On boot, read these; set `protocol_state.current_state = 0x40` only when provisioned and verified.

---
## Heartbeat on the UI
- Heartbeat messages don’t need to be the raw serial logs. The UI can simply poll `/api/heartbeat` (or `/api/status`) every few seconds and display a green dot, uptime, and current state.
- This gives users confidence during and after provisioning without exposing serial debug transports.

---
## Error modes & validations
- Invalid PEM formatting → 400 with message
- Golden hash wrong length/encoding → 400
- Already provisioned → 409 (conflict)
- Persistence I/O error → 500 with reason

---
## Security considerations
- Lock provisioning endpoints after success, or require a temporary claim token/password.
- Bind Host public key tightly to the device once set; require explicit reset to change it.
- Consider including an attestation challenge/response to defend against token cloning.

---
## Minimal contracts (inputs/outputs)
Inputs:
- Host public key (PEM)
- Golden hash (hex/base64)
Outputs:
- Token public key (PEM)
- Optional attestation report
- Provisioned state boolean
Success criteria:
- Device stores host key + golden hash and reports `provisioned=true`.
- Subsequent boots treat device as paired and hide provisioning UI.

---
## Next steps to implement
1) Add new endpoints in `api.c` (state, token_info, host_submit, confirm, heartbeat).
2) Add simple persistence layer (flash sector) with CRC.
3) Build UI wizard in `index.html` to call the new endpoints.
4) Gate endpoints by `!provisioned` and add a factory reset path.

(We can implement these in small PRs. Let me know and I’ll start with the endpoints + dummy persistence, then wire the UI.)
