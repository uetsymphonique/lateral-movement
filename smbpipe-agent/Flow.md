# smbpipe-agent — Flow

**Entry:** `main()` accept loop (`main.go`) · **Artifact summary:** passive pipe server — creates masquerading named pipe, serves one encrypted command per connection via cmd.exe

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1a | agent creates duplex byte-mode pipe `\\.\pipe\oraclexa` (FIRST_PIPE_INSTANCE, DACL BA/SY-only) | listening pipe instance [network] → #2 | Command and Control / T1095 — Non-Application Layer Protocol | NPFS object-dir entry `oraclexa`; recreated each cycle after disconnect |
| 1b | agent creates duplex byte-mode pipe `\\.\pipe\oraclexa` (FIRST_PIPE_INSTANCE, DACL BA/SY-only) | listening pipe instance [network] → #2 | Stealth / T1036.005 — Masquerading: Match Legitimate Resource Name or Location | NPFS object-dir entry `oraclexa`; recreated each cycle after disconnect |
| 2 | agent accepts SMB-originated client on pipe via overlapped ConnectNamedPipe | inbound pipe connect [network] → #3 | Command and Control / T1095 — Non-Application Layer Protocol | remote client rides tcp/445 IPC$; 1 h idle slot timeout |
| 3 | agent reads 16-byte salt frame, derives per-connection AES-256-GCM keys via pinned static X25519 ECDH | session keys established [no-artifact] → #4 #5 | Command and Control / T1573.002 — Encrypted Channel: Asymmetric Cryptography | keys baked at build time; only salt visible on wire |
| 4 | agent reads and decrypts sealed command frame from pipe | decrypted command in memory [no-artifact] → #5 | Command and Control / T1573.001 — Encrypted Channel: Symmetric Cryptography | frames ≤16 MB, commands ≤64 KB; nonce counter replay check |
| 5 | agent executes received command via `cmd.exe /c`, captures combined stdout/stderr | child cmd.exe process [process] → #6 | Execution / T1059.003 — Command and Scripting Interpreter: Windows Command Shell | parent = agent process; runs as caller's privilege level |
| 6 | agent seals output frame and writes it back to connected pipe instance | encrypted SMB write [network] | Command and Control / T1573.001 — Encrypted Channel: Symmetric Cryptography | single request/response; flush+disconnect+re-listen follows |
