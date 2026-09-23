# smbpipe-agent-svc — Flow

**Entry:** `main()` (`main.go`)  ·  **Artifact summary:** passive pipe server — on SCM start re-launches itself detached, then serves one encrypted command per connection via cmd.exe over a masquerading pipe

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1a | agent launched by SCM re-launches itself as a detached process and exits | detached child process [process] → #2 | Execution / T1569.002 — System Services: Service Execution | parent services.exe in session 0; child console-less, orphaned at SCM start timeout, same LocalSystem context |
| 1b | agent launched by SCM re-launches itself as a detached process and exits | detached child process [process] → #2 | Stealth / T1036.009 — Masquerading: Break Process Trees | parent services.exe in session 0; child console-less, orphaned at SCM start timeout, same LocalSystem context |
| 2a | agent creates byte-mode duplex pipe `\\.\pipe\oraclexa_svc` (FIRST_PIPE_INSTANCE, DACL BA/SY-only) | listening pipe instance [network] → #3 | Command and Control / T1095 — Non-Application Layer Protocol | NPFS object-dir entry `oraclexa_svc`; recreated each cycle after disconnect |
| 2b | agent creates byte-mode duplex pipe `\\.\pipe\oraclexa_svc` (FIRST_PIPE_INSTANCE, DACL BA/SY-only) | listening pipe instance [network] → #3 | Stealth / T1036.005 — Masquerading: Match Legitimate Resource Name or Location | NPFS object-dir entry `oraclexa_svc`; recreated each cycle after disconnect |
| 3 | agent accepts SMB-originated client on pipe via overlapped ConnectNamedPipe | inbound pipe connect [network] → #4 | Command and Control / T1095 — Non-Application Layer Protocol | remote client rides tcp/445 IPC$; 1 h idle slot timeout |
| 4 | agent reads 16-byte salt frame, derives per-connection AES-256-GCM keys via pinned static X25519 ECDH | session keys established [no-artifact] → #5 | Command and Control / T1573.002 — Encrypted Channel: Asymmetric Cryptography | keys baked at build time; only salt visible on wire; no forward secrecy |
| 5 | agent reads and decrypts sealed command frame from pipe | decrypted command in memory [no-artifact] → #6 | Command and Control / T1573.001 — Encrypted Channel: Symmetric Cryptography | frames ≤16 MB, commands ≤64 KB; nonce counter replay check |
| 6 | agent executes received command via `cmd.exe /c`, captures combined stdout/stderr | child cmd.exe process [process] → #7 | Execution / T1059.003 — Command and Scripting Interpreter: Windows Command Shell | parent = agent process; LocalSystem when launched via SCM |
| 7 | agent seals output frame and writes it back to connected pipe instance | encrypted SMB write [network] | Command and Control / T1573.001 — Encrypted Channel: Symmetric Cryptography | single request/response; flush+disconnect+re-listen follows |
