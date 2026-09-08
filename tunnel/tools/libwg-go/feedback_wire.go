package main

import "encoding/binary"

// WGH1 uses STUN-shaped control packets inside the established transport.
// HELLO/ACK are 20 bytes; old servers echo HELLO unchanged, never ACK it.
// REPORT adds optional attribute 0xc001: uint64 sequence + 256 stream bits.
// Keep this wire definition identical in the Android and proxy repositories.
const (
	feedbackHello      = 1
	feedbackAck        = 2
	feedbackReport     = 3
	feedbackReportSize = 64
)

type feedbackMask [32]byte

func (m feedbackMask) contains(id byte) bool { return m[id/8]&(1<<(id%8)) != 0 }
func (m *feedbackMask) add(id byte)          { m[id/8] |= 1 << (id % 8) }

func feedbackHeader(kind byte, nonce [7]byte) []byte {
	b := make([]byte, 20)
	b[1] = 0x11
	copy(b[4:12], []byte{0x21, 0x12, 0xa4, 0x42, 'W', 'G', 'H', '1'})
	b[12] = kind
	copy(b[13:], nonce[:])
	return b
}

func isFeedbackPacket(b []byte) bool {
	return len(b) >= 20 && b[0] == 0 && b[1] == 0x11 &&
		string(b[4:12]) == "\x21\x12\xa4\x42WGH1"
}

func feedbackPacket(kind byte, nonce [7]byte, seq uint64, mask feedbackMask) []byte {
	b := feedbackHeader(kind, nonce)
	if kind == feedbackReport {
		b = append(b, make([]byte, feedbackReportSize-20)...)
		binary.BigEndian.PutUint16(b[2:4], 44)
		binary.BigEndian.PutUint16(b[20:22], 0xc001)
		binary.BigEndian.PutUint16(b[22:24], 40)
		binary.BigEndian.PutUint64(b[24:32], seq)
		copy(b[32:], mask[:])
	}
	return b
}

func parseFeedback(b []byte) (kind byte, nonce [7]byte, seq uint64, mask feedbackMask, ok bool) {
	if !isFeedbackPacket(b) {
		return
	}
	kind = b[12]
	copy(nonce[:], b[13:20])
	switch kind {
	case feedbackHello, feedbackAck:
		ok = len(b) == 20 && b[2] == 0 && b[3] == 0
	case feedbackReport:
		ok = len(b) == feedbackReportSize && binary.BigEndian.Uint16(b[2:4]) == 44 &&
			binary.BigEndian.Uint16(b[20:22]) == 0xc001 && binary.BigEndian.Uint16(b[22:24]) == 40
		if ok {
			seq = binary.BigEndian.Uint64(b[24:32])
			copy(mask[:], b[32:])
		}
	}
	return
}
