/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/pion/stun/v3"
)

// Pion v5.0.13 reads NONCE/REALM from the initial Allocate reply before its
// ERROR-CODE. A terminal refusal without those challenge attributes (e.g. 437)
// consequently becomes ErrAttributeNotFound. Observe that one transaction so
// we can restore its error code without rewriting packets or Pion's auth flow.
// After its first reply, the data path only pays one atomic load per packet.
type allocateResponseConn struct {
	net.PacketConn
	remote  string
	done    atomic.Bool
	mu      sync.Mutex
	sent    bool
	txid    [stun.TransactionIDSize]byte
	refusal *stun.TurnError
}

func (c *allocateResponseConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.done.Load() {
		m := &stun.Message{Raw: b}
		if m.Decode() == nil && m.Type == stun.NewType(stun.MethodAllocate, stun.ClassRequest) && !m.Contains(stun.AttrMessageIntegrity) {
			c.mu.Lock()
			if !c.sent {
				c.sent, c.txid = true, m.TransactionID
			}
			c.mu.Unlock()
		}
	}
	return c.PacketConn.WriteTo(b, addr)
}

func (c *allocateResponseConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil && !c.done.Load() && addr != nil && addr.String() == c.remote {
		m := &stun.Message{Raw: b[:n]}
		if m.Decode() == nil && m.Type.Method == stun.MethodAllocate &&
			(m.Type.Class == stun.ClassErrorResponse || m.Type.Class == stun.ClassSuccessResponse) {
			c.mu.Lock()
			if c.sent && m.TransactionID == c.txid && !c.done.Load() {
				var code stun.ErrorCodeAttribute
				if m.Type.Class == stun.ClassErrorResponse && code.GetFrom(m) == nil && code.Code != stun.CodeUnauthorized {
					code.Reason = append([]byte(nil), code.Reason...)
					c.refusal = &stun.TurnError{StunMessageType: m.Type, ErrorCodeAttr: code}
				}
				c.done.Store(true)
			}
			c.mu.Unlock()
		}
	}
	return n, addr, err
}

func (c *allocateResponseConn) allocationError(err error) error {
	c.done.Store(true)
	if errors.Is(err, stun.ErrAttributeNotFound) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.refusal != nil {
			return c.refusal
		}
	}
	return err
}
