# smbpipe-agent-svc — Build

**Toolchain:** Go (`go.exe`, see Dev toolchain table in craft-payload/SKILL.md)

## Build

From this directory (`resources/payloads/lateral-movement/smbpipe-agent-svc/`):

```powershell
go mod tidy
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags="-s -w" -o smbpipe-agent-svc.exe .
```

Cross-compile from Linux/WSL equivalent:

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o smbpipe-agent-svc.exe .
```

## Options

| Flag / setting | Effect |
|---|---|
| `$env:GOOS="windows"; $env:GOARCH="amd64"` | Cross-compile target — Windows x64 (DC01 in Phase 4) |
| `-ldflags="-s -w"` | Strip symbol table and DWARF debug info |
| Dependency | `golang.org/x/sys` — pipe creation (`CreateNamedPipeW`), `DETACHED_PROCESS` / `CREATE_NEW_PROCESS_GROUP`, `svc.IsWindowsService` |

The `go build .` command compiles `main.go` plus both `internal/` packages (`pipeio`, `securechan`) in one pass.

## Output

- **Artifact:** `smbpipe-agent-svc.exe` (~2.5 MB static Windows x64 binary) in this directory
- **Dev-env verify:** console path only (no admin required) — run `smbpipe-agent-svc.exe` and confirm it prints `[+] Listening on \\.\pipe\oraclexa_svc` and that the pipe exists. The SCM service-detach path is lab-verified on DC01 (`exec` → service create/start/delete, then `pipe oraclexa_svc "whoami"` returned `nt authority\system`).

## Keeping in sync

This payload duplicates `../smbpipe-agent/`'s `main.go` + `internal/` packages. When re-syncing, copy the files verbatim and update only the module paths (`smbpipe-agent/internal/...` → `smbpipe-agent-svc/internal/...`) in `main.go`, `internal/securechan/securechan.go`, and `go.mod`. The protocol and pinned ECDH keys must stay identical to `smbpipe-agent` and `go-thehash`.
