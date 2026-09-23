// Package securechan implements the encrypted request/response channel on top
// of a connected named-pipe handle: static X25519 ECDH with pinned peer keys,
// per-connection key derivation, and length-prefixed AES-256-GCM frames with
// replay-protected nonces.
//
// Handshake (must be the first exchange on every connection):
//
//	client -> agent : [4-byte LE len=16][16-byte random salt]
//	both sides      : HKDF-SHA256(ECDH(static keys), salt) -> two directional keys
//
// Every subsequent frame is [4-byte LE len][12-byte nonce][ciphertext+tag]
// with the length header as AAD and a strictly increasing counter in the
// nonce. The salt makes session keys unique per connection even though the
// ECDH inputs are static; there is deliberately no forward secrecy.
package securechan

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"

	"smbpipe-agent-svc/internal/pipeio"
)

// Static X25519 identity keys, pinned at build time on both sides.
var (
	agentPrivKey = mustDecodeHex("605843f5a3472b7458df00a70c4c5a8d9b0fe636c743fd2d2c36ecc34c170ba7")
	clientPubKey = mustDecodeHex("1208c672a836da32b5dde1084a6f42e88b0516d937f3032754db8480f8b20402")
)

const (
	SaltSize     = 16 // per-connection HKDF salt sent by the client
	NonceSize    = 12 // 4-byte direction prefix + 8-byte BE counter
	hkdfInfo     = "smbpipe-oraclexa-v1"
	ioTimeout    = 10 * time.Second // per-operation deadline once connected
	maxFrameLen  = 16*1024*1024 - NonceSize - gcmOverhead
	gcmOverhead  = 16
	counterStart = 0 // first sealed frame uses counter 1
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("bad embedded key: %v", err))
	}
	return b
}

// hkdfSHA256 implements RFC 5869 extract-and-expand (stdlib-only alternative
// to golang.org/x/crypto/hkdf).
func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)

	var okm, t []byte
	for counter := byte(1); len(okm) < length; counter++ {
		expander := hmac.New(sha256.New, prk)
		expander.Write(t)
		expander.Write(info)
		expander.Write([]byte{counter})
		t = expander.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length]
}

// MaxMessageLen returns the largest plaintext Write accepts for this cipher's
// framing (frame cap minus nonce and tag).
func MaxMessageLen() int { return maxFrameLen }

// frameCipher seals/opens framed messages under one direction key.
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
	fc := &frameCipher{aead: aead}
	if _, err := rand.Read(fc.prefix[:]); err != nil {
		return nil, err
	}
	fc.counter = counterStart
	return fc, nil
}

func (fc *frameCipher) seal(msg []byte) ([]byte, error) {
	fc.counter++
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, uint32(NonceSize+len(msg)+gcmOverhead))

	var nonce [NonceSize]byte
	copy(nonce[:4], fc.prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], fc.counter)

	out := make([]byte, 4, 4+NonceSize+len(msg)+gcmOverhead)
	copy(out, header)
	out = append(out, nonce[:]...)
	out = fc.aead.Seal(out, nonce[:], msg, header)
	return out, nil
}

// open verifies the header matches the body length, checks that the frame
// carries the next expected counter value, and decrypts with the header as AAD.
func (fc *frameCipher) open(header []byte, body []byte) ([]byte, error) {
	if len(body) < NonceSize+gcmOverhead {
		return nil, errors.New("encrypted frame too short")
	}
	if binary.LittleEndian.Uint32(header) != uint32(len(body)) {
		return nil, errors.New("frame length header mismatch")
	}
	expected := make([]byte, 8)
	binary.BigEndian.PutUint64(expected, fc.counter+1)
	if !hmac.Equal(body[NonceSize-8:NonceSize], expected) {
		return nil, errors.New("unexpected nonce counter")
	}
	fc.counter++
	return fc.aead.Open(nil, body[:NonceSize], body[NonceSize:], header)
}

// Conn is an established encrypted channel over one connected pipe instance.
type Conn struct {
	H    windows.Handle
	send *frameCipher
	recv *frameCipher
}

// deriveDirectionKeys expands the static-static ECDH shared secret with the
// client's per-connection salt into independent client->server and
// server->client keys.
func deriveDirectionKeys(salt []byte) (clientToServer, serverToClient []byte, err error) {
	priv, err := ecdh.X25519().NewPrivateKey(agentPrivKey)
	if err != nil {
		return nil, nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(clientPubKey)
	if err != nil {
		return nil, nil, err
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	okm := hkdfSHA256(shared, salt, []byte(hkdfInfo), 64)
	return okm[:32], okm[32:], nil
}

// ServerHandshake consumes the client's salt frame and derives both
// directional ciphers for the agent side of the channel.
func ServerHandshake(h windows.Handle) (*Conn, error) {
	header := make([]byte, 4)
	if err := pipeio.ReadFull(h, header, ioTimeout); err != nil {
		return nil, fmt.Errorf("read salt header: %w", err)
	}
	if binary.LittleEndian.Uint32(header) != SaltSize {
		return nil, fmt.Errorf("expected %d-byte salt frame, got len %d", SaltSize, binary.LittleEndian.Uint32(header))
	}
	salt := make([]byte, SaltSize)
	if err := pipeio.ReadFull(h, salt, ioTimeout); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}

	c2s, s2c, err := deriveDirectionKeys(salt)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}
	recv, err := newFrameCipher(c2s)
	if err != nil {
		return nil, err
	}
	send, err := newFrameCipher(s2c)
	if err != nil {
		return nil, err
	}
	return &Conn{H: h, send: send, recv: recv}, nil
}

// Read receives and decrypts one framed message.
func (c *Conn) Read() ([]byte, error) {
	header := make([]byte, 4)
	if err := pipeio.ReadFull(c.H, header, ioTimeout); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(header)
	if length < NonceSize+gcmOverhead || length > maxFrameLen {
		return nil, fmt.Errorf("invalid frame length: %d", length)
	}
	body := make([]byte, length)
	if err := pipeio.ReadFull(c.H, body, ioTimeout); err != nil {
		return nil, err
	}
	return c.recv.open(header, body)
}

// Write encrypts and sends one framed message.
func (c *Conn) Write(msg []byte) error {
	if len(msg) > MaxMessageLen() {
		return fmt.Errorf("message too large: %d bytes", len(msg))
	}
	frame, err := c.send.seal(msg)
	if err != nil {
		return err
	}
	return pipeio.WriteAll(c.H, frame, ioTimeout)
}
