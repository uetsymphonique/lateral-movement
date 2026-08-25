// Package session establishes SMB connections authenticated via Pass-the-Hash.
package session

import (
	"encoding/hex"
	"fmt"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

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
