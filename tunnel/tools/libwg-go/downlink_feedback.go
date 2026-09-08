package main

import (
	"context"
	"crypto/rand"
	"sync/atomic"
	"time"
)

// Capability is scoped to one transport attempt, never inherited by a
// replacement connection. A reflected HELLO from a legacy server is not ACK.
type clientStreamControl struct {
	nonce   [7]byte
	capable atomic.Bool
}

func (s *stream) newFeedbackControl() *clientStreamControl {
	var c *clientStreamControl
	if s.feedbackEnabled && len(s.sessionID) == 16 {
		c = &clientStreamControl{}
		if _, err := rand.Read(c.nonce[:]); err != nil {
			c = nil
		}
	}
	s.control.Store(c)
	return c
}

func (c *clientStreamControl) keepalive() []byte {
	if c == nil {
		return stunBindingIndication
	}
	return feedbackHeader(feedbackHello, c.nonce)
}

func (c *clientStreamControl) receive(b []byte) bool {
	if !isFeedbackPacket(b) {
		return false
	}
	kind, nonce, _, _, ok := parseFeedback(b)
	if c != nil && ok && kind == feedbackAck && nonce == c.nonce {
		c.capable.Store(true)
	}
	return true // never forward control (including malformed/echoed control) to WG
}

func (s *stream) enqueueControl(b []byte) bool {
	p := packetPool.Get().([]byte)[:len(b)]
	copy(p, b)
	select {
	case s.in <- p:
		return true
	default:
		packetPool.Put(p[:cap(p)])
		return false
	}
}

// One reporter owns the sequence for the entire UUID, across all credential
// groups. Check clocks locally once a second, but send only on state changes
// and the existing 25s keepalive grid. Repeat changes on two paths and once
// after a second to tolerate UDP loss without creating a reconnect storm.
type downlinkReporter struct {
	seq      uint64
	last     feedbackMask
	lastGrid int64
	sent     bool
	repeatAt time.Time
}

func (r *downlinkReporter) update(streams []*stream, now time.Time) {
	var mask feedbackMask
	for _, s := range streams {
		if s.id >= 0 && s.id < 256 && s.ready.Load() && !s.dispatchStale(now) {
			mask.add(byte(s.id))
		}
	}
	grid := now.Truncate(keepaliveInterval).UnixNano()
	changed := !r.sent || mask != r.last
	repeat := !r.repeatAt.IsZero() && !now.Before(r.repeatAt)
	if !changed && !repeat && grid == r.lastGrid {
		return
	}
	r.seq++
	sent := 0
	for _, s := range streams {
		c := s.control.Load()
		if !s.ready.Load() || c == nil || !c.capable.Load() {
			continue
		}
		// If all paths are stale, explicitly clear the preference via any
		// remaining uplink. The server also expires lost reports on its own.
		if mask != (feedbackMask{}) && (s.id < 0 || s.id > 255 || !mask.contains(byte(s.id))) {
			continue
		}
		if s.enqueueControl(feedbackPacket(feedbackReport, c.nonce, r.seq, mask)) {
			sent++
		}
		if sent == 2 {
			break
		}
	}
	if sent == 0 {
		return
	}
	r.sent, r.last, r.lastGrid = true, mask, grid
	if changed {
		r.repeatAt = now.Add(time.Second)
	} else {
		r.repeatAt = time.Time{}
	}
}

func runDownlinkFeedback(ctx context.Context, streams []*stream) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var r downlinkReporter
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.update(streams, now)
		}
	}
}
