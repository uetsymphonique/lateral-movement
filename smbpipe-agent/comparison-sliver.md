# smbpipe-agent vs Sliver named-pipe C2 — Comparison

Reference implementation read from source: BishopFox Sliver (`implant/sliver/pivots/named-pipe_windows.go`, `pivots.go`, `transports/pivotclients/namedpipe_windows.go`, vendored `github.com/lesnuages/go-winio/pipe.go`). Purpose: validate our design choices against a production C2 and identify what is worth adopting.

## 1. Architecture comparison

| Aspect | Sliver | smbpipe-agent |
|---|---|---|
| Pipe creation | go-winio fork with `RemoteClientMode: true` (clears `FILE_PIPE_REJECT_REMOTE_CLIENTS`) | direct `windows.CreateNamedPipeW` without the reject flag |
| Listening instances | exactly **one pending instance** at any time (`listenerRoutine` creates the next only after a client binds) | same single-instance model (`serveOne` → next instance created after bind) |
| Accept loop | goroutine-per-connection; accept errors swallowed with `continue` — never exits | sequential one-command-per-connection; per-connection errors logged + swallowed; dead listener recreated by 1 s retry loop |
| First instance | `FILE_CREATE` with `SYNCHRONIZE`-only access → initially-disconnected state; SD applied to first instance only | `FILE_FLAG_FIRST_PIPE_INSTANCE` on first create (anti-hijack); SD applied there too |
| Wire framing | 4-byte LE length prefix, max-frame cap, zero-length frames rejected | identical: 4-byte LE prefix, 64 KB cmd / 16 MB output caps |
| Client connect | `DialPipe` — `GENERIC_READ\|GENERIC_WRITE`, busy-retry every 10 ms within 2 s timeout | go-smb open with write-enabled DesiredAccess mask (root-cause fix), fails hard when busy |

Sliver's client requesting read+write up front independently confirms our second root cause (go-smb's read-only default mask makes SRV2 drop the TCP connection on write).

## 2. Function usage / stealth comparison

| Behavior | Sliver | smbpipe-agent | Stealth implication |
|---|---|---|---|
| API layer for creation | `ntCreateNamedPipeFile` — NT native (ntdll), bypasses Win32 wrappers; path via `rtlDosPathNameToNtPathName` | `CreateNamedPipeW` (kernel32) | Sliver evades shallow userland hooks on Win32 wrappers; modern EDR hooks ntdll/kernel callbacks anyway, so benefit is marginal vs. the cost of hand-rolled syscall plumbing |
| DACL when unspecified | empty SD → `rtlDefaultNpAcl` — byte-for-byte the default NPFS ACL every legitimate service pipe carries | explicit `D:P(A;;GA;;;BA)(A;;GA;;;SY)` (stricter than default: no CreatorOwner/Everyone entries, Protected flag) | Default ACL blends in perfectly under ACL diffing; ours stands out slightly to an analyst but shrinks hijack surface — deliberate trade-off for this plan's detection goals |
| Client SQOS flag | `SECURITY_SQOS_PRESENT \| SECURITY_ANONYMOUS` on open — server cannot `ImpersonateNamedPipeClient` to steal the client token | not set (go-smb does not expose SQOS over SMB CREATE) | Hygiene worth copying if the channel is ever reused where the server side is untrusted; requires patching go-smb — deferred |
| I/O model | overlapped I/O + IO completion port → ConnectNamedPipe can be cancelled; enables deadlines | blocking synchronous ReadFile/WriteFile | Not a stealth difference — robustness. Sync blocking means a stuck connection pins the listening slot indefinitely |
| Waiting for a free slot | polls `CreateFile` every 10 ms, avoids `WaitNamedPipeW` (unreliable over remote pipes) | none | Neutral for stealth; polling pattern is what makes the single-instance busy window survivable |

## 3. Verdict

At the logic layer the two designs are near-identical (single pending instance, 4-byte LE framing, retry-on-error) — independent confirmation that our architecture matches production practice, including Microsoft's canonical pipe-server loop.

Differences live at the system-API layer, where Sliver trades source complexity for hook evasion and cancellable I/O. Our simpler stack is the right fit for an emulation plan whose goal is observable behavior.

**Adopted already:** single-instance sequencing, first-instance protection, strict DACL, swallow-per-connection-errors, size caps.

**Policy:** forking and patching upstream repos (go-smb, others) is acceptable when a capability genuinely requires it.

## 4. Change roadmap

### Stage 1 — now (client-only, low cost) — DONE
1. **Busy-retry in `execViaPipe`** (go-thehash): wrap the pipe open in a ~10 ms retry loop with a 2 s overall timeout, mirroring Sliver's `DialPipe` — mitigates the single-instance busy window. No agent change, no wire-protocol change, Detection Criteria unaffected.
   Implemented as `openPipeWithRetry` (main.go): retries on `STATUS_PIPE_BUSY` and `STATUS_PIPE_NOT_AVAILABLE` (both mapped errors matched via `errors.Is`), 10 ms poll, 2 s deadline.
2. Rebuild + one regression pass through the lab channel.

### Stage 2 — when long-lived sessions / robustness are needed (agent-side) — DONE
3. **Overlapped I/O + ~10 s read/write deadlines**: DONE — `internal/pipeio` (`Op`/`Connect`/`ReadFull`/`WriteAll`) wraps every pipe operation in `OVERLAPPED` + event wait with `CancelIoEx` on timeout; `ConnectNamedPipe` idles up to 1 h then recycles the slot.
4. **Channel encryption — Static ECDH with pinned peer keys**: DONE — `internal/securechan` (agent) and the "encrypted pipe channel" block in go-thehash (client; separate module, kept in mirror).
   - Handshake: client sends a random 16-byte salt per connection → HKDF-SHA256(X25519 static-static ECDH, salt) → two directional AES-256-GCM keys (one round-trip frame).
   - Frame format: `[4-byte LE len][12-byte nonce][ciphertext+tag]`; nonce = 4-byte random direction prefix ‖ 8-byte strictly increasing counter (replay-resistant, no clock sync); length header is AAD.
   - Rationale vs alternatives: real C2 channel encryption always negotiates keys at connect time (CS RSA, Mythic/Sliver ECDH) — never bakes a shared symmetric key into the binary, so ECDH matches observed tradecraft on the wire while PSK does not; and it strictly dominates PSK against binary-string key extraction for ~30–40 extra lines (stdlib-only: `crypto/ecdh`, `crypto/aes`, hand-rolled HKDF).
   - Not forward-secret (static keys) — accepted; ephemeral keys would drift toward the full Sliver-style design already ruled out.
   - Structural SMB signals remain observable (pipe creation, IPC$ connects, traffic volume/timing); only content-level signatures are lost.
   - **Deployment note:** protocol changed incompatibly — agent and go-thehash must be redeployed together; an old binary against a new one fails at the handshake.

### Stage 3 — only if goals shift toward evasion/prevention
5. **NT-native pipe creation** (`NtCreateFile` path like Sliver) — evades shallow Win32 hooks.
6. **SQOS `SECURITY_ANONYMOUS` client flag** — requires the accepted go-smb patch/fork.
