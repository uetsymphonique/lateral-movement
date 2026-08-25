// Package enum implements host enumeration over DCE/RPC: share and session
// listing via MS-SRVS, local user listing via MS-SAMR.
package enum

import (
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssamr"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
)

// bindSrvsvc opens IPC$ and binds to the MS-SRVS (srvsvc) interface.
// The caller must call the returned cleanup function.
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

// Shares enumerates all shares on the target via MS-SRVS NetShareEnumAll.
func Shares(session *smb.Connection, target string) error {
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

// Sessions enumerates active SMB sessions on the target via MS-SRVS NetSessionEnum.
func Sessions(session *smb.Connection) error {
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

// Users enumerates local user accounts on the target via MS-SAMR.
// netbiosName is the NetBIOS computer name (e.g. "DC01"); pass "" to auto-detect.
func Users(session *smb.Connection, netbiosName string) error {
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
