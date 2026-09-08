package main

import (
	"testing"
	"time"
)

func TestFeedbackRequiresMatchingAckAndResetsOnReconnect(t *testing.T) {
	s := &stream{feedbackEnabled: true, sessionID: make([]byte, 16)}
	c := s.newFeedbackControl()
	if !c.receive(c.keepalive()) || c.capable.Load() {
		t.Fatal("legacy echo enabled feedback")
	}
	wrong := c.nonce
	wrong[0] ^= 1
	c.receive(feedbackHeader(feedbackAck, wrong))
	if c.capable.Load() {
		t.Fatal("foreign ACK enabled feedback")
	}
	c.receive(feedbackHeader(feedbackAck, c.nonce))
	if !c.capable.Load() {
		t.Fatal("matching ACK ignored")
	}
	fresh := s.newFeedbackControl()
	fresh.receive(feedbackHeader(feedbackAck, c.nonce))
	if fresh.capable.Load() {
		t.Fatal("replacement inherited old capability")
	}
}

func feedbackTestStream(id int, now time.Time) *stream {
	s := &stream{feedbackEnabled: true, id: id, sessionID: make([]byte, 16), in: make(chan []byte, 8)}
	s.activity.Store(newStreamActivity(now, 0))
	s.ready.Store(true)
	c := s.newFeedbackControl()
	c.capable.Store(true)
	return s
}

func readFeedbackReport(t *testing.T, s *stream) (uint64, feedbackMask) {
	t.Helper()
	select {
	case p := <-s.in:
		defer packetPool.Put(p[:cap(p)])
		kind, _, seq, mask, ok := parseFeedback(p)
		if !ok || kind != feedbackReport {
			t.Fatal("not a report")
		}
		return seq, mask
	default:
		t.Fatal("missing report")
		return 0, feedbackMask{}
	}
}

func TestFeedbackReportsLossRecoveryAndAllStale(t *testing.T) {
	now := time.Now()
	bad, good := feedbackTestStream(0, now), feedbackTestStream(255, now)
	bad.activity.Load().noteRx(now.Add(-40 * time.Second))
	streams := []*stream{bad, good}
	var r downlinkReporter
	r.update(streams, now)
	seq, mask := readFeedbackReport(t, good)
	if mask.contains(0) || !mask.contains(255) || len(bad.in) != 0 {
		t.Fatal("report used stale path or mask")
	}
	// A lost update is repeated before the next 25s probe window.
	r.update(streams, now.Add(time.Second))
	seq2, _ := readFeedbackReport(t, good)
	if seq2 <= seq {
		t.Fatal("retry sequence did not advance")
	}
	bad.activity.Load().noteRx(now.Add(2 * time.Second))
	r.update(streams, now.Add(2*time.Second))
	_, mask = readFeedbackReport(t, good)
	readFeedbackReport(t, bad)
	if !mask.contains(0) || !mask.contains(255) {
		t.Fatal("recovery not advertised")
	}
	bad.activity.Load().noteRx(now.Add(-40 * time.Second))
	good.activity.Load().noteRx(now.Add(-40 * time.Second))
	r.update(streams, now.Add(3*time.Second))
	_, mask = readFeedbackReport(t, good)
	readFeedbackReport(t, bad)
	if mask != (feedbackMask{}) {
		t.Fatal("all-stale fallback not advertised")
	}
}

func TestFeedbackDoesNotSendReportsToLegacyOrBlockOnFullQueue(t *testing.T) {
	now := time.Now()
	s := feedbackTestStream(0, now)
	s.control.Load().capable.Store(false)
	var r downlinkReporter
	r.update([]*stream{s}, now)
	if len(s.in) != 0 {
		t.Fatal("report sent without negotiation")
	}
	s.control.Load().capable.Store(true)
	for i := 0; i < cap(s.in); i++ {
		s.in <- nil
	}
	r.update([]*stream{s}, now) // must not wait for the transport's blocked writer
	if r.sent {
		t.Fatal("full queue counted as a sent report")
	}
	for len(s.in) > 0 {
		<-s.in
	}
}
