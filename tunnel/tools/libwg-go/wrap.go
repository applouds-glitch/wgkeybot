// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
 "net"
 "time"
	"golang.org/x/crypto/chacha20"
)

const (
	wrapNonceLen = 12
	wrapKeyLen   = 32
)

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

func wrapPacket(key, payload []byte) ([]byte, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	out := make([]byte, wrapNonceLen+len(payload))
	if _, err := rand.Read(out[:wrapNonceLen]); err != nil {
		return nil, fmt.Errorf("wrap: nonce gen: %w", err)
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key, out[:wrapNonceLen])
	if err != nil {
		return nil, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(out[wrapNonceLen:], payload)
	return out, nil
}

func unwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen {
		return 0, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	if len(wire) < wrapNonceLen {
		return 0, errors.New("wrap: short packet (no nonce)")
	}
	nonce := wire[:wrapNonceLen]
	ciphertext := wire[wrapNonceLen:]
	if len(ciphertext) > len(dst) {
		return 0, errors.New("wrap: dst buffer too small")
	}
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return 0, fmt.Errorf("wrap: cipher init: %w", err)
	}
	cipher.XORKeyStream(dst[:len(ciphertext)], ciphertext)
	return len(ciphertext), nil
}

// wrapPacketConn оборачивает net.PacketConn в WRAP-шифрование.
// Каждый исходящий пакет: [12 байт nonce | ciphertext]
// Каждый входящий пакет: распаковывается обратно.
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
    return len(p), err // возвращаем длину оригинала, не зашифрованного
}

func (w *wrapPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
    buf := make([]byte, len(p)+wrapNonceLen)
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
