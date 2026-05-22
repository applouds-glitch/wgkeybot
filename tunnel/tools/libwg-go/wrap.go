// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
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
)

var wrapCounter atomic.Uint64
var rtpSSRC uint32

func initSSRC(key []byte) {
	h := sha256.Sum256(key)
	rtpSSRC = binary.BigEndian.Uint32(h[:4])
}

// ── RTP header (12 bytes) ────────────────────────────────────────────────────

func putHeader(buf []byte, counter uint64, payloadLen int) {
	buf[0] = 0x80 // V=2, P=0, X=0, CC=0
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
	binary.BigEndian.PutUint32(buf[8:12], rtpSSRC)               // ssrc
	_ = payloadLen
}

func readHeader(buf []byte) (counter uint64, payloadLen int) {
	ts := uint64(binary.BigEndian.Uint32(buf[4:8]))
	counter = ts / 960
	payloadLen = 0
	return
}

// ── XOR keystream ────────────────────────────────────────────────────────────

func xorKeystream(key []byte, counter uint64, length int) []byte {
	if length <= 0 {
		return nil
	}
	ks := make([]byte, length)
	var state [32]byte
	h := sha256.New()
	h.Write(key)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	h.Write(ctr[:])
	h.Sum(state[:0])
	for off := 0; off < length; off += 32 {
		n := length - off
		if n > 32 {
			n = 32
		}
		copy(ks[off:], state[:n])
		if off+32 < length {
			state = sha256.Sum256(state[:])
		}
	}
	return ks
}

func xorInPlace(key []byte, counter uint64, data []byte) {
	ks := xorKeystream(key, uint64(uint32(counter)), len(data))
	for i := range data {
		data[i] ^= ks[i]
	}
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
	initSSRC(key)
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

func wrapPacket(key, payload []byte) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes", wrapKeyLen)
	}
	counter := (wrapCounter.Add(1) - 1) % wrapCounterMod

	padLen := randPadLen()
	plaintext := make([]byte, len(payload)+padLen+wrapPadLen)
	copy(plaintext, payload)
	if padLen > 0 {
		rand.Read(plaintext[len(payload) : len(payload)+padLen])
	}
	binary.BigEndian.PutUint16(plaintext[len(plaintext)-wrapPadLen:], uint16(padLen))

	xorInPlace(key, counter, plaintext)

	out := make([]byte, wrapHdrLen+len(plaintext))
	putHeader(out[:wrapHdrLen], counter, len(plaintext))
	copy(out[wrapHdrLen:], plaintext)
	return out, nil
}

func unwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("wrap: key must be %d bytes", wrapKeyLen)
	}
	if len(wire) < wrapHdrLen+wrapPadLen {
		return 0, errors.New("wrap: short packet")
	}
	counter, _ := readHeader(wire[:wrapHdrLen])
	ciphertext := wire[wrapHdrLen:]
	if len(ciphertext) < wrapPadLen {
		return 0, errors.New("wrap: encrypted payload too short")
	}
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)
	xorInPlace(key, counter, plaintext)

	padLen := int(binary.BigEndian.Uint16(plaintext[len(plaintext)-wrapPadLen:]))
	if padLen == wrapCoverMark {
		return 0, nil
	}
	if padLen > wrapMaxPad || wrapPadLen+padLen > len(plaintext) {
		return 0, errors.New("wrap: invalid padding")
	}
	n := len(plaintext) - wrapPadLen - padLen
	if n > len(dst) {
		return 0, errors.New("wrap: dst buffer too small")
	}
	copy(dst, plaintext[:n])
	return n, nil
}

func wrapCoverPacket(key []byte) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes", wrapKeyLen)
	}
	counter := (wrapCounter.Add(1) - 1) % wrapCounterMod

	bodyLen := 30 + randPadLen()*4
	plaintext := make([]byte, bodyLen+wrapPadLen)
	rand.Read(plaintext[:bodyLen])
	binary.BigEndian.PutUint16(plaintext[bodyLen:], wrapCoverMark)

	xorInPlace(key, counter, plaintext)

	out := make([]byte, wrapHdrLen+len(plaintext))
	putHeader(out[:wrapHdrLen], counter, len(plaintext))
	copy(out[wrapHdrLen:], plaintext)
	return out, nil
}

// ── PacketConn wrapper ───────────────────────────────────────────────────────

type wrapPacketConn struct {
	inner net.PacketConn
	key   []byte
}

func wrapConn(inner net.PacketConn, key []byte) net.PacketConn {
	return &wrapPacketConn{inner: inner, key: key}
}

func (w *wrapPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	enc, err := wrapPacket(w.key, p)
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
