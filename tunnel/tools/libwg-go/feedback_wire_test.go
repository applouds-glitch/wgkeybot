package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestFeedbackWireFixture(t *testing.T) {
	// Shared fixture guards the separately built Android/server protocol.
	want, err := hex.DecodeString("0011002c2112a442574748310301020304050607c0010028000000000000002a0100000000000000000000000000000000000000000000000000000000000080")
	if err != nil {
		t.Fatal(err)
	}
	nonce := [7]byte{1, 2, 3, 4, 5, 6, 7}
	var mask feedbackMask
	mask.add(0)
	mask.add(255)
	got := feedbackPacket(feedbackReport, nonce, 42, mask)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire mismatch: %x", got)
	}
	k, n, s, m, ok := parseFeedback(want)
	if !ok || k != feedbackReport || n != nonce || s != 42 || m != mask {
		t.Fatal("fixture parse failed")
	}
	for size := 0; size < len(want); size++ {
		if _, _, _, _, ok := parseFeedback(want[:size]); ok {
			t.Fatalf("accepted truncated report: %d", size)
		}
	}
	for _, offset := range []int{0, 1, 2, 3, 4, 8, 12, 20, 21, 22, 23} {
		bad := append([]byte(nil), want...)
		bad[offset] ^= 0x80
		if _, _, _, _, ok := parseFeedback(bad); ok {
			t.Fatalf("accepted malformed field at %d", offset)
		}
	}
}
