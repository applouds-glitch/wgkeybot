// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20"
)

const (
	wrapKeyLen    = 32
	wrapHdrLen    = 12 // RTP-like header: V=2|PT|seq(2)|ts(4)|ssrc(4)
	wrapMaxPad    = 32
	wrapPadLen    = 2
	wrapCoverMark = 0xFFFF
	// wrapCounterMod bounds the counter so counter*960 always fits the 32-bit
	// RTP timestamp field (max safe counter floor((2^32-1)/960) = 4 473 924).
	// Past it the server's timestamp round-trip (ts/960) no longer recovers
	// the counter, the keystream index diverges, and every packet fails to
	// decrypt. Must stay in sync with the server's wrapCounterMod.
	wrapCounterMod = 4_000_000

	// wgTransportOverhead is WireGuard's per-packet transport overhead
	// (16-byte message_data header + 16-byte Poly1305 tag) on top of the inner
	// IP packet. The largest payload handed to wrapPacket is tunnelMTU + this.
	wgTransportOverhead = 32

	// wrapDefaultMaxBody is the payload+padding ceiling for the default 1280
	// tunnel MTU, used until SetWrapMTU learns the real interface MTU.
	wrapDefaultMaxBody = 1280 + wgTransportOverhead
)

// wrapCounter is the legacy SHA keystream's counter. That keystream is derived
// from (key, counter) alone — it ignores SSRC — so its counter must stay unique
// across every stream of the process, or two streams would share a keystream at
// the same counter. ChaCha senders fold their SSRC into the nonce and therefore
// keep a per-stream counter instead (see wrapTxState).
var wrapCounter atomic.Uint64

func nextGlobalWrapCounter() uint64 {
	return (wrapCounter.Add(1) - 1) % wrapCounterMod
}

// wrapTxState is one stream's outbound WRAP identity: the RTP SSRC written into
// every header and the counter that feeds both the RTP seq/timestamp and the
// ChaCha20 nonce.
//
// Per-stream rather than process-wide for two reasons. The counter drives
// seq (counter&0xFFFF) and ts (counter*960) within a single SSRC, so a shared
// counter made each stream's RTP sequence advance in steps of ~8 — a stream
// that appears to be losing 87% of its packets, which is exactly what this
// layer is trying not to look like. And a shared counter reached its wrap
// point N times sooner with N streams. The server has kept a per-connection
// ChaCha counter for the same reasons; this brings the client's uplink in line.
//
// SSRC and counter are packed into one word so a sender claims both in a single
// atomic step: two goroutines per stream send WRAP packets (the TX loop and the
// keepalive/cover loop), and a torn pair would reuse a keystream.
type wrapTxState struct {
	// state: SSRC in the high 32 bits, next counter in the low 32. The counter
	// is < wrapCounterMod, so it never overflows into the SSRC half.
	state atomic.Uint64
}

func newWrapTxState() *wrapTxState {
	s := &wrapTxState{}
	s.state.Store(uint64(randU32()) << 32)
	return s
}

// next claims the (ssrc, counter) pair for one outbound packet.
//
// Reaching wrapCounterMod does not merely reset the counter: replaying the same
// counter under the same SSRC would repeat the (ssrc, dir, counter) nonce and
// with it the ChaCha20 keystream, and XORing two packets encrypted under one
// keystream cancels it out. So a wrap opens a fresh nonce domain — new random
// SSRC, counter back to zero. The server reads the SSRC out of every packet
// header (it never pins the one it first saw), so the switch needs no
// negotiation and no coordinated deploy. It also keeps the RTP story straight:
// a timestamp jumping back to zero is impossible within one SSRC, but perfectly
// ordinary for a newly started one.
func (w *wrapTxState) next() (uint32, uint64) {
	if clientCipher != cipherChaCha {
		// Legacy SHA keystream: SSRC-independent, so the counter has to come
		// from the process-wide sequence.
		return w.ssrc(), nextGlobalWrapCounter()
	}
	for {
		old := w.state.Load()
		ssrc := uint32(old >> 32)
		counter := old & 0xFFFFFFFF
		next := old + 1
		if counter+1 >= wrapCounterMod {
			next = uint64(randU32()) << 32
		}
		if w.state.CompareAndSwap(old, next) {
			return ssrc, counter
		}
	}
}

// ssrc reports the SSRC currently in use, without claiming a counter.
func (w *wrapTxState) ssrc() uint32 { return uint32(w.state.Load() >> 32) }

// wrapMaxBody caps payload+padding so the obfuscation jitter never inflates a
// near-full WireGuard packet past the tuned tunnel MTU. Without this a full-size
// packet plus up to wrapMaxPad random bytes overflows links whose path MTU sits
// just below full size and gets silently dropped — large transfers stall while
// small ones (chat) pass. Small packets keep their full 0..wrapMaxPad cover
// jitter; only packets already near the ceiling lose padding.
var wrapMaxBody atomic.Int64

func init() { wrapMaxBody.Store(wrapDefaultMaxBody) }

// SetWrapMTU recomputes the padding ceiling from the active tunnel MTU. Called
// once the WireGuard interface MTU is known; a non-positive mtu is ignored.
func SetWrapMTU(mtu int) {
	if mtu <= 0 {
		return
	}
	wrapMaxBody.Store(int64(mtu + wgTransportOverhead))
}

// wrapCipher selects the WRAP keystream, signalled on the wire by the RTP X-bit
// (byte[0] & 0x10). Kept byte-identical with the server's wrap.go:
//
//	cipherSHA    (X-bit clear, byte[0]=0x80) — legacy SHA-256 hash-chain keystream
//	cipherChaCha (X-bit set,   byte[0]=0x90) — ChaCha20 keystream
//
// The server auto-detects the marker to decrypt each client and to reply in the
// same keystream, so old clients (always 0x80) keep working while new clients
// move to ChaCha20. IMPORTANT: deploy the server before shipping ChaCha clients
// — an old server only knows the SHA keystream and cannot decode 0x90 packets.
type wrapCipher uint8

const (
	cipherSHA    wrapCipher = 0
	cipherChaCha wrapCipher = 1
	wrapXBit                = 0x10 // RTP extension bit, repurposed as the cipher-version marker

	// clientCipher is the keystream this build uses for every outbound WRAP
	// packet. Flip this one constant to change what a new client emits.
	// Decryption is always auto-detected from the marker, so a server reply in
	// either keystream is understood regardless of this value.
	clientCipher = cipherChaCha
)

// Direction domain-separation for the ChaCha nonce. The client encrypts uplink
// with wrapDirClient and decrypts downlink with wrapDirServer; the server
// mirrors it. Combined with a per-connection random SSRC (also folded into the
// nonce) this guarantees a given (key, counter) never produces the same
// keystream in both directions, across two devices sharing a key, or across
// sessions — closing the nonce-reuse that a counter-only nonce left open. The
// SHA path ignores these (its keystream is counter-only, unchanged).
const (
	wrapDirClient byte = 0
	wrapDirServer byte = 1
	wrapTxDir          = wrapDirClient // this build (client) sends uplink
	wrapRxDir          = wrapDirServer // ...and receives downlink from the server
)

// cipherFromHeader reports which keystream a wire packet uses, read from the RTP
// X-bit. buf must be at least 1 byte.
func cipherFromHeader(buf []byte) wrapCipher {
	if buf[0]&wrapXBit != 0 {
		return cipherChaCha
	}
	return cipherSHA
}

// randU32 returns a cryptographically random 32-bit value, used for the
// per-connection RTP SSRC.
func randU32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// ── RTP header (12 bytes) ────────────────────────────────────────────────────

func putHeader(buf []byte, counter uint64, payloadLen int, cipher wrapCipher, ssrc uint32) {
	buf[0] = 0x80 // V=2, P=0, X=0, CC=0
	if cipher == cipherChaCha {
		buf[0] |= wrapXBit // X=1: signal ChaCha20 keystream to the server
	}
	marker := byte(0)
	if counter == 0 {
		marker = 0x80
	}
	if counter%50 == 0 {
		buf[1] = marker | 0x60 // PT=96
	} else {
		buf[1] = marker | 0x6F // PT=111 (Opus)
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(counter&0xFFFF)) // seq
	binary.BigEndian.PutUint32(buf[4:8], uint32(counter*960))    // ts (Opus 48kHz)
	binary.BigEndian.PutUint32(buf[8:12], ssrc)                  // ssrc (per-conn random)
	_ = payloadLen
}

func readHeader(buf []byte) (counter uint64, payloadLen int) {
	ts := uint64(binary.BigEndian.Uint32(buf[4:8]))
	counter = ts / 960
	payloadLen = 0
	return
}

// ── Keystreams ───────────────────────────────────────────────────────────────

// xorInPlace applies the SHA-256 hash-chain keystream (keyed by key+counter) to
// data in place. Each 32-byte keystream block is generated on the fly and XORed
// with crypto/subtle (vectorized), so no keystream buffer is allocated per
// packet. Legacy path; wire-identical to the pre-ChaCha implementation.
func xorInPlace(key []byte, counter uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	var state [32]byte
	h := sha256.New()
	h.Write(key)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(uint32(counter)))
	h.Write(ctr[:])
	h.Sum(state[:0])
	for off := 0; off < len(data); off += 32 {
		n := len(data) - off
		if n > 32 {
			n = 32
		}
		subtle.XORBytes(data[off:off+n], data[off:off+n], state[:n])
		if off+32 < len(data) {
			state = sha256.Sum256(state[:])
		}
	}
}

// wrapChaChaNonce builds the 12-byte ChaCha20 nonce from the per-conn SSRC, the
// direction byte, and the WRAP counter. Layout (must stay byte-identical with
// the server): ssrc[0:4] BE ‖ dir[4] ‖ 0[5:8] ‖ counter[8:12] BE. The counter is
// < wrapCounterMod so it fits uint32 losslessly; ssrc+dir make the nonce unique
// per connection and per direction so keystream is never reused across them.
func wrapChaChaNonce(ssrc uint32, dir byte, counter uint64) [chacha20.NonceSize]byte {
	var nonce [chacha20.NonceSize]byte
	binary.BigEndian.PutUint32(nonce[0:4], ssrc)
	nonce[4] = dir
	binary.BigEndian.PutUint32(nonce[8:12], uint32(counter))
	return nonce
}

// xorChaCha XORs data in place with the ChaCha20 keystream keyed by key, nonce =
// wrapChaChaNonce(ssrc, dir, counter). Same inputs ⇒ same keystream, so
// decryption is stateless per packet. Must stay byte-identical with the server.
func xorChaCha(key []byte, counter uint64, ssrc uint32, dir byte, data []byte) {
	if len(data) == 0 {
		return
	}
	nonce := wrapChaChaNonce(ssrc, dir, counter)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce[:])
	if err != nil {
		return
	}
	c.XORKeyStream(data, data)
}

// xorKeystream applies the keystream for the given cipher in place. cipherSHA →
// legacy hash-chain (ssrc/dir ignored); cipherChaCha → xorChaCha(ssrc, dir).
func xorKeystream(cipher wrapCipher, key []byte, counter uint64, ssrc uint32, dir byte, data []byte) {
	if cipher == cipherChaCha {
		xorChaCha(key, counter, ssrc, dir, data)
		return
	}
	xorInPlace(key, counter, data)
}

// ── Key management ───────────────────────────────────────────────────────────

func genWrapKeyHex() (string, error) {
	key := make([]byte, wrapKeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("wrap: key gen: %w", err)
	}
	return hex.EncodeToString(key), nil
}

func decodeWrapKey(enabled bool, raw string) ([]byte, error) {
	if !enabled {
		return nil, nil
	}
	if raw == "" {
		return nil, errors.New("wrap requires wrap-key")
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("wrap-key invalid hex: %w", err)
	}
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap-key must decode to %d bytes (got %d)", wrapKeyLen, len(key))
	}
	return key, nil
}

// ── Packet encrypt / decrypt ─────────────────────────────────────────────────

func randPadLen() int {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	return int(b[0]) % (wrapMaxPad + 1)
}

// wrapMaxOverhead is how much longer a wrapped packet can be than its payload:
// the header plus the largest possible random pad plus the pad-length trailer.
// Hot TX paths size their scratch buffer with it.
const wrapMaxOverhead = wrapHdrLen + wrapMaxPad + wrapPadLen

// wrapPacketInto encrypts payload for the outbound (uplink) direction into dst
// and returns the number of bytes written. It is the allocation-free form of
// wrapPacket for the per-packet TX paths, where the caller owns a scratch
// buffer for the lifetime of its goroutine. dst must have room for
// len(payload)+wrapMaxOverhead; dst and payload must not overlap.
func wrapPacketInto(dst, key, payload []byte, tx *wrapTxState) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("wrap: key must be %d bytes", wrapKeyLen)
	}
	ssrc, counter := tx.next()

	padLen := randPadLen()
	// MTU-safety: clamp padding so payload+padding never exceeds wrapMaxBody.
	// Full-size packets ship unpadded (room <= 0); small packets keep their
	// cover jitter. Prevents the random pad from black-holing near-full packets.
	if room := int(wrapMaxBody.Load()) - len(payload); padLen > room {
		if room < 0 {
			room = 0
		}
		padLen = room
	}
	plainLen := len(payload) + padLen + wrapPadLen
	total := wrapHdrLen + plainLen
	if len(dst) < total {
		return 0, fmt.Errorf("wrap: dst buffer too small (%d < %d)", len(dst), total)
	}
	// Header + plaintext are built contiguously in dst, then the plaintext
	// region is encrypted in place.
	out := dst[:total]
	putHeader(out[:wrapHdrLen], counter, plainLen, clientCipher, ssrc)
	plaintext := out[wrapHdrLen:]
	copy(plaintext, payload)
	if padLen > 0 {
		rand.Read(plaintext[len(payload) : len(payload)+padLen])
	}
	binary.BigEndian.PutUint16(plaintext[plainLen-wrapPadLen:], uint16(padLen))
	xorKeystream(clientCipher, key, counter, ssrc, wrapTxDir, plaintext)
	return total, nil
}

// wrapPacket is the allocating form of wrapPacketInto, kept for the cold paths
// (session handshake, keepalive, cover traffic) where a per-goroutine scratch
// buffer would not pay for itself.
func wrapPacket(key, payload []byte, tx *wrapTxState) ([]byte, error) {
	out := make([]byte, len(payload)+wrapMaxOverhead)
	n, err := wrapPacketInto(out, key, payload, tx)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

func unwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("wrap: key must be %d bytes", wrapKeyLen)
	}
	if len(wire) < wrapHdrLen+wrapPadLen {
		return 0, errors.New("wrap: short packet")
	}
	counter, _ := readHeader(wire[:wrapHdrLen])
	cipher := cipherFromHeader(wire[:wrapHdrLen])
	ssrc := binary.BigEndian.Uint32(wire[8:12]) // sender's per-conn SSRC → nonce
	ciphertext := wire[wrapHdrLen:]
	if len(ciphertext) < wrapPadLen {
		return 0, errors.New("wrap: encrypted payload too short")
	}
	// Decrypt in place into dst (no scratch allocation).
	if len(ciphertext) > len(dst) {
		return 0, errors.New("wrap: dst buffer too small")
	}
	plaintext := dst[:len(ciphertext)]
	copy(plaintext, ciphertext)
	xorKeystream(cipher, key, counter, ssrc, wrapRxDir, plaintext)

	padLen := int(binary.BigEndian.Uint16(plaintext[len(plaintext)-wrapPadLen:]))
	if padLen == wrapCoverMark {
		return 0, nil
	}
	if padLen > wrapMaxPad || wrapPadLen+padLen > len(plaintext) {
		return 0, errors.New("wrap: invalid padding")
	}
	n := len(plaintext) - wrapPadLen - padLen
	return n, nil
}

func wrapCoverPacket(key []byte, tx *wrapTxState) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes", wrapKeyLen)
	}
	ssrc, counter := tx.next()

	bodyLen := 30 + randPadLen()*4
	plainLen := bodyLen + wrapPadLen
	out := make([]byte, wrapHdrLen+plainLen)
	putHeader(out[:wrapHdrLen], counter, plainLen, clientCipher, ssrc)
	plaintext := out[wrapHdrLen:]
	rand.Read(plaintext[:bodyLen])
	binary.BigEndian.PutUint16(plaintext[bodyLen:], wrapCoverMark)
	xorKeystream(clientCipher, key, counter, ssrc, wrapTxDir, plaintext)
	return out, nil
}

// ── PacketConn wrapper (unused legacy helper; kept for API completeness) ──────

type wrapPacketConn struct {
	inner net.PacketConn
	key   []byte
	tx    *wrapTxState
}

func wrapConn(inner net.PacketConn, key []byte) net.PacketConn {
	return &wrapPacketConn{inner: inner, key: key, tx: newWrapTxState()}
}

func (w *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	enc, err := wrapPacket(w.key, p, w.tx)
	if err != nil {
		return 0, err
	}
	_, err = w.inner.WriteTo(enc, addr)
	return len(p), err
}

func (w *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p))
	n, addr, err := w.inner.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	n, err = unwrapPacket(w.key, buf[:n], p)
	return n, addr, err
}

func (w *wrapPacketConn) Close() error                       { return w.inner.Close() }
func (w *wrapPacketConn) LocalAddr() net.Addr                { return w.inner.LocalAddr() }
func (w *wrapPacketConn) SetDeadline(t time.Time) error      { return w.inner.SetDeadline(t) }
func (w *wrapPacketConn) SetReadDeadline(t time.Time) error  { return w.inner.SetReadDeadline(t) }
func (w *wrapPacketConn) SetWriteDeadline(t time.Time) error { return w.inner.SetWriteDeadline(t) }

func randInterval(minSec, maxSec int) time.Duration {
	b := make([]byte, 1)
	rand.Read(b)
	return time.Duration(minSec+int(b[0])%(maxSec-minSec+1)) * time.Second
}
