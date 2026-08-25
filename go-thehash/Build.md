# go-thehash — Build

**Toolchain:** Go (`go.exe`, see Dev toolchain table in craft-payload/SKILL.md)

## Build

From this directory (`resources/payloads/lateral-movement/go-thehash/`):

```powershell
go mod tidy
$env:GOOS = "windows"; $env:GOARCH = "amd64"
go build -ldflags="-s -w" -o go-thehash.exe .
```

Cross-compile from Linux/WSL equivalent:

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o go-thehash.exe .
```

## Options

| Flag / setting | Effect |
|---|---|
| `$env:GOOS="windows"; $env:GOARCH="amd64"` | Cross-compile target — Windows x64 (IIS01 in Phase 4) |
| `-ldflags="-s -w"` | Strip symbol table and DWARF debug info |
| `replace github.com/jfjallid/go-smb => ./go-smb` | Vendored go-smb library (see `go.mod`) — all subcommands use `TreeConnect`/`OpenFile`/`ReadFile`/`WriteFile` from `./go-smb/smb/session.go`; no external network fetch needed for it |

No external dependencies beyond the vendored go-smb. The `pipe` subcommand uses only the standard library (`crypto/ecdh`, `crypto/aes`, `crypto/cipher`, `crypto/hmac`, `crypto/sha256`, `encoding/binary`, `math/rand`-free entropy via `crypto/rand`).

## Output

- **Artifact:** `go-thehash.exe` (~4.9 MB static Windows x64 binary) in this directory. The `go build .` command compiles `main.go` plus all five `internal/` packages in one pass.
- **Dev-env verify:** benign dry-run without a target:

```
.\go-thehash.exe pipe
# Expected: "Usage: go-thehash pipe <target> <domain> <user> <nt-hash> <pipe-name> <command>" on stderr, exit 1
```

Do not run with real target/hash arguments outside the lab host.
