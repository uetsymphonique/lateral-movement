# smbpipe-agent — Build

**Toolchain:** Go (`go.exe`, see Dev toolchain table in craft-payload/SKILL.md)

## Build

From this directory (`resources/payloads/lateral-movement/smbpipe-agent/`):

```powershell
go mod tidy
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags="-s -w" -o smbpipe-agent.exe .
```

Cross-compile from Linux/WSL equivalent:

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o smbpipe-agent.exe .
```

## Options

| Flag / setting | Effect |
|---|---|
| `$env:GOOS="windows"; $env:GOARCH="amd64"` | Cross-compile target — Windows x64 (DC01 in Phase 4) |
| `-ldflags="-s -w"` | Strip symbol table and DWARF debug info |
| Dependency | Only `golang.org/x/sys` — the pipe is created via `CreateNamedPipeW` directly |

The `go build .` command compiles `main.go` plus both `internal/` packages (`pipeio`, `securechan`) in one pass; no per-package build step is needed.

### Why not go-winio

Root causes (server-side `FILE_PIPE_REJECT_REMOTE_CLIENTS` in go-winio, client-side read-only DesiredAccess in go-smb) are documented in `README.md` → "Root cause". Do not reintroduce go-winio as a dependency when refactoring.

## Output

- **Artifact:** `smbpipe-agent.exe` (~2.6 MB static Windows x64 binary) in this directory
- **Dev-env verify:** none practical — running the agent creates a real named pipe (`\\.\pipe\oraclexa`) on the dev host, which is live behavior. Verify by inspection (`go vet ./...`) or defer to the lab host.
