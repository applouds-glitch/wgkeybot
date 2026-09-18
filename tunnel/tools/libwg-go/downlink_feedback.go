package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"time"
)

// Downlink feedback (WGH1) tells the server which streams this client can
// actually hear.
//
// The server picks the stream for each downstream packet by upstream freshness
// alone (streamStaleAfter in vk-turn-proxy): a stream it keeps receiving from
// looks healthy to it. A path that dies in one direction only — the relay stops
// delivering peer→client while client→peer still flows — therefore stays in the
// server's rotation indefinitely. That is exactly what a field log from
// 2026-09-18 showed: at 08:16 the client stopped hearing eight of ten streams,
// the server kept receiving from all ten for another 2m20s and kept sending a
// share of every downstream burst into the deaf ones, and WireGuard never got
// a handshake response through. The client already knows which streams are
// deaf (dispatchStale); this puts that knowledge where the downstream choice is
// made.
//
// Wire format: feedback_wire.go, byte-identical to vk-turn-proxy's copy (a
// shared hex fixture guards it). The keepalive becomes a HELLO; a server that
// speaks WGH1 answers ACK — which is also the stream's liveness echo — and an
// older one reflects HELLO as a plain STUN keepalive, so capability is only ever
// proven by a matching ACK. The server applies a report for 75s and ignores one
// whose mask names none of its current streams, so a lost or stale report can
// only fall back to "use every stream", never pin traffic to a dead path.
//
// This was part of the TURN layer rolled back to 1.9.4 on 2026-09-17 and came
// back on its own, as one mechanism, once the field log showed the failure it
// exists for.

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

	// Log state only: what the log last said, so it speaks on transitions
	// (capability confirmed, the excluded set changing) and not on every report.
	announced    bool
	lastExcluded string
}

func (r *downlinkReporter) update(streams []*stream, now time.Time) {
	var mask feedbackMask
	var excluded []int
	ready := 0
	for _, s := range streams {
		if !s.ready.Load() {
			continue
		}
		ready++
		if s.id >= 0 && s.id < 256 && !s.dispatchStale(now) {
			mask.add(byte(s.id))
		} else {
			excluded = append(excluded, s.id)
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
	r.logTransition(excluded, ready)
	r.sent, r.last, r.lastGrid = true, mask, grid
	if changed {
		r.repeatAt = now.Add(time.Second)
	} else {
		r.repeatAt = time.Time{}
	}
}

// logTransition reports what the server has just been told, once per change.
// Streams still coming up are not "excluded" — they are simply not ready — so
// a session's start is silent apart from the capability line.
func (r *downlinkReporter) logTransition(excluded []int, ready int) {
	if !r.announced {
		r.announced = true
		turnLog("[FEEDBACK] server acknowledged WGH1 — reporting downstream health")
	}
	key := fmt.Sprint(excluded)
	if key == r.lastExcluded || (len(excluded) == 0 && r.lastExcluded == "") {
		return
	}
	r.lastExcluded = key
	switch {
	case len(excluded) == 0:
		turnLog("[FEEDBACK] report %d: every ready stream hears the server again (%d)", r.seq, ready)
	case len(excluded) == ready:
		turnLog("[FEEDBACK] report %d: no ready stream hears the server — asking it to use all %d", r.seq, ready)
	default:
		turnLog("[FEEDBACK] report %d: server to skip streams %v (%d of %d ready are deaf)", r.seq, excluded, len(excluded), ready)
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
