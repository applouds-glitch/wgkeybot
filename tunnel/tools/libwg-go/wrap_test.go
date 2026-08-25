// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func testWrapKey() []byte {
	key := make([]byte, wrapKeyLen)
	for i := range key {
		key[i] = byte(i * 7)
	}
	return key
}

// decodeAsServer decrypts a client-produced WRAP packet the way the server does:
// counter recovered from the RTP timestamp, SSRC read out of the header, and the
// uplink direction byte. Mirrors server/wrap.go unwrapPacketDir(_, _, _,
// wrapRxDir) where the server's wrapRxDir == wrapDirClient. Kept independent of
// this package's own unwrapPacket so a change that silently breaks the wire
// contract with the server fails here.
func decodeAsServer(t *testing.T, key, wire []byte) (payload []byte, ssrc uint32, counter uint64) {
	t.Helper()
	if len(wire) < wrapHdrLen+wrapPadLen {
		t.Fatalf("short packet: %d bytes", len(wire))
	}
	ts := uint64(binary.BigEndian.Uint32(wire[4:8]))
	counter = ts / 960
	ssrc = binary.BigEndian.Uint32(wire[8:12])
	if cipherFromHeader(wire) != cipherChaCha {
		t.Fatalf("expected ChaCha marker (X-bit) in header byte %#x", wire[0])
	}

	plaintext := append([]byte(nil), wire[wrapHdrLen:]...)
	nonce := wrapChaChaNonce(ssrc, wrapDirClient, counter)
	c, err := chacha20.NewUnauthenticatedCipher(key, nonce[:])
	if err != nil {
		t.Fatalf("chacha init: %v", err)
	}
	c.XORKeyStream(plaintext, plaintext)

	padLen := int(binary.BigEndian.Uint16(plaintext[len(plaintext)-wrapPadLen:]))
	if padLen == wrapCoverMark {
		return nil, ssrc, counter
	}
	if padLen > wrapMaxPad || wrapPadLen+padLen > len(plaintext) {
		t.Fatalf("invalid padding %d", padLen)
	}
	return plaintext[:len(plaintext)-wrapPadLen-padLen], ssrc, counter
}

// TestWrapServerRoundTrip is the wire-contract test: what wrapPacketInto emits
// must decode under the server's rules.
func TestWrapServerRoundTrip(t *testing.T) {
	key := testWrapKey()
	tx := newWrapTxState()
	payload := []byte("wireguard transport packet payload")
	dst := make([]byte, len(payload)+wrapMaxOverhead)

	n, err := wrapPacketInto(dst, key, payload, tx)
	if err != nil {
		t.Fatalf("wrapPacketInto: %v", err)
	}
	got, ssrc, counter := decodeAsServer(t, key, dst[:n])
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
	if counter != 0 {
		t.Errorf("first packet counter = %d, want 0", counter)
	}
	if ssrc != tx.ssrc() {
		t.Errorf("header SSRC %d != stream SSRC %d", ssrc, tx.ssrc())
	}
}

// TestWrapCoverServerRoundTrip covers the cover-traffic packet, which the server
// recognises by the wrapCoverMark trailer and drops.
func TestWrapCoverServerRoundTrip(t *testing.T) {
	key := testWrapKey()
	tx := newWrapTxState()

	wire, err := wrapCoverPacket(key, tx)
	if err != nil {
		t.Fatalf("wrapCoverPacket: %v", err)
	}
	got, _, _ := decodeAsServer(t, key, wire)
	if got != nil {
		t.Fatalf("cover packet decoded to %d payload bytes, want none", len(got))
	}
}

// TestWrapSequenceIsPerStream is the point of the per-stream counter: within one
// SSRC the RTP sequence must advance by exactly one per packet. A process-wide
// counter made it step by the number of active streams, which reads as heavy
// packet loss to anything parsing the RTP header.
func TestWrapSequenceIsPerStream(t *testing.T) {
	key := testWrapKey()
	a, b := newWrapTxState(), newWrapTxState()
	payload := []byte("payload")
	dst := make([]byte, len(payload)+wrapMaxOverhead)

	const packets = 16
	for i := 0; i < packets; i++ {
		// Interleave the two streams: a shared counter would show up as gaps.
		for _, tx := range []*wrapTxState{a, b} {
			n, err := wrapPacketInto(dst, key, payload, tx)
			if err != nil {
				t.Fatalf("wrapPacketInto: %v", err)
			}
			if tx != a {
				continue
			}
			seq := binary.BigEndian.Uint16(dst[2:4])
			if int(seq) != i {
				t.Fatalf("packet %d: seq = %d, want %d (counter shared between streams?)", i, seq, i)
			}
			_, _, counter := decodeAsServer(t, key, dst[:n])
			if counter != uint64(i) {
				t.Fatalf("packet %d: counter = %d, want %d", i, counter, i)
			}
		}
	}
}

// TestWrapCounterWrapRotatesSSRC pins the nonce-reuse fix: at the counter's
// wrap point the stream must move to a fresh SSRC instead of replaying
// (ssrc, dir, counter) — that triple is the whole ChaCha20 nonce, so a replay
// would hand two packets the same keystream.
func TestWrapCounterWrapRotatesSSRC(t *testing.T) {
	tx := newWrapTxState()
	firstSSRC := tx.ssrc()

	// Jump to one packet short of the wrap point.
	tx.state.Store(uint64(firstSSRC)<<32 | (wrapCounterMod - 1))

	ssrc, counter := tx.next()
	if ssrc != firstSSRC || counter != wrapCounterMod-1 {
		t.Fatalf("last packet before wrap = (%d, %d), want (%d, %d)", ssrc, counter, firstSSRC, wrapCounterMod-1)
	}

	ssrc, counter = tx.next()
	if counter != 0 {
		t.Errorf("counter after wrap = %d, want 0", counter)
	}
	if ssrc == firstSSRC {
		t.Error("SSRC unchanged across counter wrap: (ssrc, dir, counter) repeats and the keystream is reused")
	}
}

// TestWrapNoNonceReuseUnderConcurrency guards the packing of SSRC and counter
// into one word. Two goroutines per stream emit WRAP packets (the TX loop and
// the keepalive/cover loop); if they could claim the pair non-atomically, two
// packets would share a nonce.
func TestWrapNoNonceReuseUnderConcurrency(t *testing.T) {
	tx := newWrapTxState()

	const goroutines = 8
	const perGoroutine = 512

	var mu sync.Mutex
	seen := make(map[uint64]struct{}, goroutines*perGoroutine)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			local := make([]uint64, 0, perGoroutine)
			for j := 0; j < perGoroutine; j++ {
				ssrc, counter := tx.next()
				local = append(local, uint64(ssrc)<<32|counter)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, nonce := range local {
				if _, dup := seen[nonce]; dup {
					t.Errorf("nonce (ssrc=%d, counter=%d) claimed twice", uint32(nonce>>32), nonce&0xFFFFFFFF)
				}
				seen[nonce] = struct{}{}
			}
		}()
	}
	wg.Wait()

	if len(seen) != goroutines*perGoroutine {
		t.Errorf("got %d distinct nonces, want %d", len(seen), goroutines*perGoroutine)
	}
}

// TestWrapPaddingRespectsMTU keeps the obfuscation jitter from inflating a
// near-full packet past the tuned tunnel MTU.
func TestWrapPaddingRespectsMTU(t *testing.T) {
	key := testWrapKey()
	tx := newWrapTxState()
	maxBody := int(wrapMaxBody.Load())

	payload := make([]byte, maxBody-4)
	dst := make([]byte, len(payload)+wrapMaxOverhead)
	n, err := wrapPacketInto(dst, key, payload, tx)
	if err != nil {
		t.Fatalf("wrapPacketInto: %v", err)
	}
	if body := n - wrapHdrLen - wrapPadLen; body > maxBody {
		t.Errorf("payload+padding = %d, exceeds wrapMaxBody %d", body, maxBody)
	}
	got, _, _ := decodeAsServer(t, key, dst[:n])
	if !bytes.Equal(got, payload) {
		t.Error("near-MTU payload did not survive the round trip")
	}
}
