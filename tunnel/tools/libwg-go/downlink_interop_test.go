package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func interopServer(t *testing.T, mode string, key []byte, binaryPath string) *net.UDPAddr {
	t.Helper()
	backend := listenFakeRelay(t)
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := backend.ReadFrom(b)
			if e != nil {
				return
			}
			backend.WriteTo(b[:n], a)
		}
	}()
	reserve := listenFakeRelay(t)
	addr := reserve.LocalAddr().(*net.UDPAddr)
	reserve.Close()
	args := []string{"-listen", addr.String(), "-connect", backend.LocalAddr().String(), "-peer-type", mode}
	if key != nil {
		args = append(args, "-wrap-key", hex.EncodeToString(key))
	}
	logPath := filepath.Join(t.TempDir(), "server.log")
	logFile, e := os.Create(logPath)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binaryPath, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if e = cmd.Start(); e != nil {
		logFile.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		logFile.Close()
		data, _ := os.ReadFile(logPath)
		if strings.Contains(string(data), "WARNING: DATA RACE") {
			t.Errorf("server race: %s", data)
		}
		if t.Failed() {
			t.Logf("server log: %s", data)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, _ := os.ReadFile(logPath)
		if strings.Contains(strings.ToLower(string(b)), "listening on") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not listen: %s", b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return addr
}

// A local stand-in for a relay, with an independently switchable downlink.
func interopRelay(t *testing.T, server *net.UDPAddr) (*net.UDPAddr, *atomic.Bool) {
	t.Helper()
	edge := listenFakeRelay(t)
	up, e := net.DialUDP("udp", nil, server)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { up.Close() })
	drop := new(atomic.Bool)
	var client atomic.Pointer[net.Addr]
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := edge.ReadFrom(b)
			if e != nil {
				return
			}
			client.Store(&a)
			up.Write(b[:n])
		}
	}()
	go func() {
		b := make([]byte, 4096)
		for {
			n, e := up.Read(b)
			if e != nil {
				return
			}
			if !drop.Load() {
				if a := client.Load(); a != nil {
					edge.WriteTo(b[:n], *a)
				}
			}
		}
	}()
	return edge.LocalAddr().(*net.UDPAddr), drop
}

func interopStream(t *testing.T, id int, peer *net.UDPAddr, mode string, key []byte, wg net.PacketConn, feedback bool, sessionIDs ...[]byte) *stream {
	t.Helper()
	s, relay := newNoDTLSTestStream(t)
	s.feedbackEnabled = feedback
	s.id = id
	s.sessionID = []byte("interop-session1")
	if len(sessionIDs) > 0 {
		if len(sessionIDs) != 1 || len(sessionIDs[0]) != 16 {
			t.Fatal("expected one 16-byte session ID")
		}
		s.sessionID = sessionIDs[0]
	}
	s.wrapKey = key
	s.wrapTx = newWrapTxState()
	a := wg.LocalAddr()
	s.peer.Store(&a)
	cert, e := selfsign.GenerateSelfSigned()
	if e != nil {
		t.Fatal(e)
	}
	s.cert = &cert
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		var e error
		switch mode {
		case "wireguard":
			e = s.runNoDTLS(ctx, relay, peer)
		case "srtp":
			e = s.runSRTP(ctx, relay, peer)
		default:
			e = s.runDTLS(ctx, relay, peer, true)
		}
		done <- e
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("client did not stop")
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for !s.ready.Load() {
		select {
		case e := <-done:
			t.Fatalf("client failed: %v", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("client not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s
}

func interopPacket(i int) []byte {
	b := make([]byte, iPacketBuffMaxSize)
	b[0] = 4
	binary.LittleEndian.PutUint32(b[4:8], uint32(i))
	copy(b[8:], []byte("interop-wireguard-payload"))
	return b[:64]
}

func interopReceived(wg net.PacketConn, wait time.Duration) map[uint32][]byte {
	got := map[uint32][]byte{}
	wg.SetReadDeadline(time.Now().Add(wait))
	b := make([]byte, 2048)
	for {
		n, _, e := wg.ReadFrom(b)
		if e != nil {
			return got
		}
		if n == 64 && b[0] == 4 {
			got[binary.LittleEndian.Uint32(b[4:8])] = append([]byte(nil), b[:n]...)
		}
	}
}

// Set WG_FEEDBACK_SERVER to the freshly built proxy binary. The optional
// WG_LEGACY_SERVER exercises the new client against the committed old proxy.
// Only relay downlink is dropped: uplink still succeeds, as on an asymmetric
// mobile path. RX clocks are advanced to the 35..90s stale window; no test
// sleeps for an entire dead-stream timeout.
func feedbackServerBinary(t *testing.T, legacy bool) string {
	t.Helper()
	name := "WG_FEEDBACK_SERVER"
	if legacy {
		name = "WG_LEGACY_SERVER"
	}
	p := os.Getenv(name)
	if p == "" {
		t.Skip("set " + name + " to run cross-repository integration")
	}
	return p
}
func waitFeedback(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("feedback condition timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func feedbackKey(mode string) []byte {
	if mode != "wireguard" && mode != "dtls_wrap" {
		return nil
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}
func TestFeedbackInteropVersions(t *testing.T) {
	for _, version := range []struct {
		name                       string
		legacyServer, legacyClient bool
	}{{"both_new", false, false}, {"old_client", false, true}, {"old_server", true, false}} {
		t.Run(version.name, func(t *testing.T) {
			binaryPath := feedbackServerBinary(t, version.legacyServer)
			for _, mode := range []string{"wireguard", "proxy_v2", "dtls_wrap", "srtp"} {
				t.Run(mode, func(t *testing.T) {
					key := feedbackKey(mode)
					if mode == "dtls_wrap" {
						mode = "proxy_v2"
					}
					peer := interopServer(t, mode, key, binaryPath)
					wg := listenFakeRelay(t)
					s := interopStream(t, 0, peer, mode, key, wg, !version.legacyClient)
					if !version.legacyClient && !version.legacyServer {
						waitFeedback(t, func() bool { return s.control.Load().capable.Load() })
					}
					// Old-client mode keeps the original 20-byte probe and sends no HELLO.
					if version.legacyClient {
						s.enqueueControl(stunBindingIndication)
					}
					for i := 0; i < 16; i++ {
						s.in <- interopPacket(i)
						time.Sleep(2 * time.Millisecond)
					}
					got := interopReceived(wg, 400*time.Millisecond)
					if len(got) != 16 {
						t.Fatalf("received %d/16", len(got))
					}
					for i := 0; i < 16; i++ {
						if !bytes.Equal(got[uint32(i)], interopPacket(i)) {
							t.Fatal("wire payload changed")
						}
					}
					if version.legacyServer && s.control.Load().capable.Load() {
						t.Fatal("legacy echo enabled feedback")
					}
				})
			}
		})
	}
}
func TestFeedbackInteropDownlinkLossAndRecovery(t *testing.T) {
	binaryPath := feedbackServerBinary(t, false)
	for _, mode := range []string{"wireguard", "proxy_v2", "dtls_wrap", "srtp"} {
		t.Run(mode, func(t *testing.T) {
			key := feedbackKey(mode)
			if mode == "dtls_wrap" {
				mode = "proxy_v2"
			}
			server := interopServer(t, mode, key, binaryPath)
			wg := listenFakeRelay(t)
			peer0, drop0 := interopRelay(t, server)
			peer1, _ := interopRelay(t, server)
			s0 := interopStream(t, 0, peer0, mode, key, wg, true)
			s1 := interopStream(t, 1, peer1, mode, key, wg, true)
			streams := []*stream{s0, s1}
			waitFeedback(t, func() bool { return s0.control.Load().capable.Load() && s1.control.Load().capable.Load() })
			for i := 0; i < 16; i++ {
				dispatchPacket(streams, 1, time.Now(), interopPacket(i))
				time.Sleep(2 * time.Millisecond)
			}
			if got := interopReceived(wg, 200*time.Millisecond); len(got) != 16 {
				t.Fatalf("healthy received %d/16", len(got))
			}
			drop0.Store(true)
			s0.activity.Load().noteRx(time.Now().Add(-40 * time.Second))
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); runDownlinkFeedback(ctx, streams) }()
			t.Cleanup(func() { cancel(); <-done })
			time.Sleep(1200 * time.Millisecond) // production reporter detects stale clock and sends mask
			for i := 100; i < 132; i++ {
				dispatchPacket(streams, 0, time.Now(), interopPacket(i))
				time.Sleep(2 * time.Millisecond)
			}
			got := interopReceived(wg, 300*time.Millisecond)
			if len(got) != 32 {
				t.Fatalf("asymmetric failure: received %d/32", len(got))
			}
			t.Log("asymmetric failure: 32/32 responses on surviving downlink")
			for i := 200; i < 203; i++ {
				dispatchPacket(streams, 0, time.Now(), interopPacket(i))
				time.Sleep(1100 * time.Millisecond)
			}
			if got := interopReceived(wg, 100*time.Millisecond); len(got) != 3 {
				t.Fatalf("rare replies: %d/3", len(got))
			}
			// Echoes bypass exclusion and let the original stream recover.
			drop0.Store(false)
			s0.enqueueControl(s0.control.Load().keepalive())
			waitFeedback(t, func() bool { return !s0.dispatchStale(time.Now()) })
			time.Sleep(1200 * time.Millisecond)
			before := s0.activity.Load().lastRx.Load()
			for i := 300; i < 332; i++ {
				dispatchPacket(streams, 1, time.Now(), interopPacket(i))
				time.Sleep(2 * time.Millisecond)
			}
			if got := interopReceived(wg, 300*time.Millisecond); len(got) != 32 {
				t.Fatalf("recovery: %d/32", len(got))
			}
			if s0.activity.Load().lastRx.Load() <= before {
				t.Fatal("recovered stream did not rejoin downlink")
			}
		})
	}
}
func TestFeedbackInteropIdleRotationWithoutReports(t *testing.T) {
	server := interopServer(t, "proxy_v2", nil, feedbackServerBinary(t, false))
	wg := listenFakeRelay(t)
	peer0, drop0 := interopRelay(t, server)
	peer1, _ := interopRelay(t, server)
	s0 := interopStream(t, 0, peer0, "proxy_v2", nil, wg, false)
	s1 := interopStream(t, 1, peer1, "proxy_v2", nil, wg, false)
	streams := []*stream{s0, s1}
	for i := 0; i < 16; i++ {
		dispatchPacket(streams, 1, time.Now(), interopPacket(i))
		time.Sleep(2 * time.Millisecond)
	}
	if got := interopReceived(wg, 200*time.Millisecond); len(got) != 16 {
		t.Fatalf("control: %d/16", len(got))
	}
	drop0.Store(true)
	for i := 200; i < 203; i++ {
		dispatchPacket(streams, 1, time.Now(), interopPacket(i))
		time.Sleep(1100 * time.Millisecond)
	}
	got := interopReceived(wg, 100*time.Millisecond)
	if len(got) == 0 {
		t.Fatal("all rare replies pinned to silent stream")
	}
	t.Logf("legacy client, no feedback: %d/3 rare replies survive one broken path", len(got))
}

func TestFeedbackInteropAllSilentThenOnePathReturns(t *testing.T) {
	server := interopServer(t, "proxy_v2", nil, feedbackServerBinary(t, false))
	wg := listenFakeRelay(t)
	peer0, drop0 := interopRelay(t, server)
	peer1, drop1 := interopRelay(t, server)
	s0 := interopStream(t, 0, peer0, "proxy_v2", nil, wg, true)
	s1 := interopStream(t, 1, peer1, "proxy_v2", nil, wg, true)
	streams := []*stream{s0, s1}
	waitFeedback(t, func() bool { return s0.control.Load().capable.Load() && s1.control.Load().capable.Load() })
	drop0.Store(true)
	drop1.Store(true)
	for _, s := range streams {
		s.activity.Load().noteRx(time.Now().Add(-40 * time.Second))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); runDownlinkFeedback(ctx, streams) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(1200 * time.Millisecond)
	for i := 0; i < 16; i++ {
		dispatchPacket(streams, 1, time.Now(), interopPacket(i))
		time.Sleep(2 * time.Millisecond)
	}
	if got := interopReceived(wg, 100*time.Millisecond); len(got) != 0 {
		t.Fatal("fault injection did not drop both paths")
	}
	// No manual reconnect or probe: data must be able to discover a returned
	// path even while the most recent client report says every path is stale.
	drop0.Store(false)
	for i := 100; i < 116; i++ {
		dispatchPacket(streams, 1, time.Now(), interopPacket(i))
		time.Sleep(2 * time.Millisecond)
	}
	if got := interopReceived(wg, 100*time.Millisecond); len(got) == 0 {
		t.Fatal("empty health report prevented recovery")
	}
	waitFeedback(t, func() bool { return !s0.dispatchStale(time.Now()) })
	time.Sleep(1200 * time.Millisecond)
	for i := 200; i < 232; i++ {
		dispatchPacket(streams, 0, time.Now(), interopPacket(i))
		time.Sleep(2 * time.Millisecond)
	}
	if got := interopReceived(wg, 200*time.Millisecond); len(got) != 32 {
		t.Fatalf("after all-silent recovery: %d/32", len(got))
	}
}

func TestFeedbackInteropMixedSessionsOnOneServer(t *testing.T) {
	key := feedbackKey("wireguard")
	server := interopServer(t, "both", key, feedbackServerBinary(t, false))
	type client struct {
		wg       net.PacketConn
		streams  []*stream
		drops    [2]*atomic.Bool
		feedback bool
	}
	// Identical stream IDs in distinct UUID sessions are intentional. New
	// clients advertise opposite masks while legacy clients send no reports.
	// A global/shared mask would break at least half of the new sessions.
	clients := make([]client, 16)
	for i := range clients {
		c := &clients[i]
		c.wg = listenFakeRelay(t)
		c.feedback = i%2 == 0
		session := []byte("mixed-session-00")
		binary.BigEndian.PutUint16(session[14:], uint16(i))
		mode := "proxy_v2"
		var clientKey []byte
		if i%4 < 2 {
			mode, clientKey = "wireguard", key
		}
		for id := 0; id < 2; id++ {
			peer, drop := interopRelay(t, server)
			c.drops[id] = drop
			c.streams = append(c.streams, interopStream(t, id, peer, mode, clientKey, c.wg, c.feedback, session))
		}
		if c.feedback {
			waitFeedback(t, func() bool {
				return c.streams[0].control.Load().capable.Load() && c.streams[1].control.Load().capable.Load()
			})
		}
	}
	for i := range clients {
		c := &clients[i]
		if !c.feedback {
			continue
		}
		bad := (i / 2) % 2
		c.drops[bad].Store(true)
		c.streams[bad].activity.Load().noteRx(time.Now().Add(-40 * time.Second))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); runDownlinkFeedback(ctx, c.streams) }()
		t.Cleanup(func() { cancel(); <-done })
	}
	time.Sleep(1200 * time.Millisecond)
	for n := 0; n < 32; n++ {
		for i, c := range clients {
			if sent, _ := dispatchPacket(c.streams, 0, time.Now(), interopPacket(i*1000+n)); !sent {
				t.Fatalf("client %d TX drop", i)
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	for i, c := range clients {
		got := interopReceived(c.wg, 100*time.Millisecond)
		if len(got) != 32 {
			t.Fatalf("client %d (feedback=%t): %d/32 responses", i, c.feedback, len(got))
		}
		for n := 0; n < 32; n++ {
			id := i*1000 + n
			if !bytes.Equal(got[uint32(id)], interopPacket(id)) {
				t.Fatalf("client %d received another session's payload", i)
			}
		}
	}
	t.Log("16 concurrent sessions / 32 streams, mixed legacy and new clients on one demux port: 512/512 responses; opposite health masks isolated")
}
