// Package session establishes SMB connections authenticated either via
// Pass-the-Hash (NTLMv2, T1550.002) or Kerberos with a plaintext domain
// password (T1078.002).
package session

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

// kerberosRealm returns the Kerberos realm to use. A realm is a DNS domain
// (e.g. "TESTLAB.LOCAL"); if only a short NetBIOS name ("TESTLAB") is given,
// the DNS suffix is taken from the fully-qualified target hostname. gokrb5
// uses the realm name directly for KDC discovery, so a flat name that is not
// DNS-resolvable would otherwise fail with "lookup TESTLAB: no such host".
func kerberosRealm(domain, target string) (string, error) {
	if strings.Contains(domain, ".") {
		return strings.ToUpper(domain), nil
	}
	if idx := strings.Index(target, "."); idx >= 0 {
		return strings.ToUpper(target[idx+1:]), nil
	}
	return "", fmt.Errorf("Kerberos needs a realm: pass the DNS domain as <domain> (e.g. TESTLAB.LOCAL) or a fully-qualified <target>")
}

// Connect establishes an SMB session using Pass-the-Hash (NTLMv2 with NT hash).
// hashHex is the 32-character hex NT hash (e.g. "41c46bf74ec071f65c7b97df4b7d672a").
func Connect(target, domain, user, hashHex string) (*smb.Connection, error) {
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

// ConnectKerb establishes an SMB session authenticated with Kerberos using a
// plaintext domain password (Valid Accounts: Domain Accounts, T1078.002).
// target must be a hostname, not an IP, so the cifs/<host> SPN can be formed.
// domain must be the Kerberos realm (the DNS domain, e.g. "TESTLAB.LOCAL"); a
// short NetBIOS name is accepted and its realm derived from the target FQDN.
// dcip optionally pins the KDC; empty lets DNS discover it via the realm.
func ConnectKerb(target, domain, user, password, dcip string) (*smb.Connection, error) {
	if net.ParseIP(target) != nil {
		return nil, fmt.Errorf("Kerberos requires a hostname target, not an IP: %s", target)
	}
	realm, err := kerberosRealm(domain, target)
	if err != nil {
		return nil, err
	}
	if dcip == "" {
		fmt.Fprintf(os.Stderr, "[!] -dcip not set; resolving KDC via DNS SRV for realm %s\n", realm)
	}
	options := smb.Options{
		Host: target,
		Port: 445,
		Initiator: &spnego.KRB5Initiator{
			User:     user,
			Password: password,
			Domain:   realm,
			SPN:      "cifs/" + target,
			DCIP:     dcip,
		},
	}
	session, err := smb.NewConnection(options)
	if err != nil {
		return nil, fmt.Errorf("Kerberos SMB connect to %s: %w", target, err)
	}
	if !session.IsAuthenticated() {
		session.Close()
		return nil, fmt.Errorf("Kerberos authentication failed for %s\\%s", domain, user)
	}
	return session, nil
}

// Dial selects Kerberos when useKrb is set, otherwise NTLM pass-the-hash.
// In the Kerberos case credential is a plaintext password; in the NTLM case
// credential is a 32-hex NT hash.
func Dial(useKrb bool, target, domain, user, credential, dcip string) (*smb.Connection, error) {
	if useKrb {
		return ConnectKerb(target, domain, user, credential, dcip)
	}
	return Connect(target, domain, user, credential)
}
