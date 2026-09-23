# go-thehash — Flow

**Entry:** `main()` dispatch (`main.go`) · **Artifact summary:** PtH SMB toolkit — file ops, service/WMI remote exec, encrypted pipe C2 client, RPC enumeration; artifacts live on the remote target, not locally

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | tool authenticates SMB2 to target tcp/445 using raw NT hash (no plaintext) | authenticated session [identity] → #2 #3 #4 #5 #6 #10 #12 #16 #17 | Lateral Movement / T1550.002 — Use Alternate Authentication Material: Pass the Hash | 4624 Logon Type 3 NTLM on target; hash passed via argv |
| 2 | tool (put) writes local file to remote share path | file created on share [file] | Lateral Movement / T1570 — Lateral Tool Transfer | follows #1 in same session; admin-share write needs local admin |
| 3 | tool (get) copies remote share file to local disk | local file created [file] | Lateral Movement / T1021.002 — Remote Services: SMB/Windows Admin Shares | staged exfil/staging pattern |
| 4 | tool (del) deletes remote share file | file deleted on share [file] | Lateral Movement / T1021.002 — Remote Services: SMB/Windows Admin Shares | often cleanup of payloads dropped by #2 |
| 5 | tool (ls) enumerates remote share directory | directory listing printed [network] | Discovery / T1083 — File and Directory Discovery | SMB2 FIND over admin share |
| 6 | tool (exec) binds DCE/RPC over `\\pipe\svcctl` on IPC$ | svcctl pipe open [network] → #7 #9 | Lateral Movement / T1021.002 — Remote Services: SMB/Windows Admin Shares | SMB2 Create on `\pipe\svcctl` visible in capture |
| 7 | tool (exec) creates transient service with random 12-char name, binPath=command | service entry created [registry] → #8 | Execution / T1569.002 — System Services: Service Execution | Event 7045; lowercase-random name; ERROR 1053 timeout expected |
| 8 | tool (exec) starts service, spawning command process under SYSTEM | child process on target [process] → #9 | Execution / T1569.002 — System Services: Service Execution | parent services.exe; SCM terminates the service process ~30 s if no SetServiceStatus |
| 9 | tool (exec) deletes service right after launch | service key deleted [registry] | Stealth / T1070 — Indicator Removal | create→start→delete within seconds |
| 10a | tool (exec-wmi) connects DCOM tcp/135 (+dynamic port) with pkt privacy | RPC connection [network] → #11 | Lateral Movement / T1021.003 — Remote Services: Distributed Component Object Model | no SMB pipe involved; transport for WMI activation |
| 10b | tool (exec-wmi) authenticates DCOM connection with raw NT hash | authenticated RPC session [identity] → #11 | Lateral Movement / T1550.002 — Use Alternate Authentication Material: Pass the Hash | hash reused across SMB and DCOM auth |
| 11a | tool (exec-wmi) invokes Win32_Process.Create with command line | child process on target [process] | Execution / T1047 — Windows Management Instrumentation | parent WmiPrvSE.exe; runs as caller context, not SYSTEM |
| 11b | tool (exec-wmi) invokes Win32_Process.Create over DCOM transport | child process spawned remotely [process] | Lateral Movement / T1021.003 — Remote Services: Distributed Component Object Model | KB names DCOM as WMI's remote transport |
| 12 | tool (pipe) opens custom named pipe over IPC$ read+write, polling on PIPE_BUSY | pipe open [network] → #13 | Command and Control / T1095 — Non-Application Layer Protocol | 10 ms poll, 2 s deadline on STATUS_PIPE_BUSY/NOT_AVAILABLE |
| 13 | tool (pipe) sends 16-byte salt, derives AES-256-GCM keys via static X25519 ECDH | encrypted channel established [no-artifact] → #14 #15 | Command and Control / T1573.002 — Encrypted Channel: Asymmetric Cryptography | pinned peer keys baked at build time; only salt visible on wire |
| 14 | tool (pipe) writes sealed command frame to pipe | encrypted SMB write [network] → #15 | Command and Control / T1573.001 — Encrypted Channel: Symmetric Cryptography | frames ≤16 MB, commands ≤64 KB |
| 15 | tool (pipe) reads sealed output frame, prints stdout | decrypted output only in memory [no-artifact] | Command and Control / T1573.001 — Encrypted Channel: Symmetric Cryptography | single request/response per connection |
| 16a | tool (enum shares) queries srvsvc NetShareEnumAll | share listing printed [network] | Discovery / T1135 — Network Share Discovery | standard admin-enum RPC interface |
| 16b | tool (enum sessions) queries srvsvc NetSessionEnum | active-session listing printed [network] | Discovery / T1033 — System Owner/User Discovery | client IP + username + idle time per session |
| 17 | tool (enum users) queries samr ListLocalUsers | local account listing printed [network] | Discovery / T1087.001 — Account Discovery: Local Account | RID + username dump, max 500 |
