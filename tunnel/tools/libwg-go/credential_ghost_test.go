package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

type dropAllocateSuccess struct{ net.PacketConn }

func (c *dropAllocateSuccess) WriteTo(b []byte, a net.Addr) (int, error) {
	m := &stun.Message{Raw: append([]byte(nil), b...)}
	if m.Decode() == nil && m.Type == stun.NewType(stun.MethodAllocate, stun.ClassSuccessResponse) {
		return len(b), nil
	}
	return c.PacketConn.WriteTo(b, a)
}
func TestLostAllocateReplyQuarantinesCredentialRelay(t *testing.T) {
	resetCredentialQuota()
	t.Cleanup(resetCredentialQuota)
	pc := listenFakeRelay(t)
	var server *turn.Server
	var err error
	server, err = turn.NewServer(turn.ServerConfig{Realm: "quota-test", AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
		return a.Username, turn.GenerateAuthKey(a.Username, "quota-test", "pass"), true
	}, QuotaHandler: func(_, _ string, _ net.Addr) bool { return server.AllocationCount() < 1 }, PacketConnConfigs: []turn.PacketConnConfig{{PacketConn: &dropAllocateSuccess{pc}, RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{RelayAddress: net.ParseIP("127.0.0.1"), Address: "127.0.0.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer resetServerHealth()
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	release, err := acquireCredentialAllocation(ctx, "user", "pass")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, err = dialAndAllocate(ctx, &stream{}, "user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
	release()
	if err == nil {
		t.Fatal("expected lost reply")
	}
	if server.AllocationCount() != 1 {
		t.Fatalf("server allocations=%d, want ghost allocation", server.AllocationCount())
	}
	t.Log("client released local lease; server still holds allocation after lost success reply")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_, _, _, _, _, err = dialAndAllocate(ctx2, &stream{}, "user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
	if !isQuotaError(err) {
		t.Fatalf("expected 486, got %v", err)
	}
	serverHealthState.Lock()
	health := serverHealthState.byAddr[pc.LocalAddr().String()]
	charged := health != nil && health.failures > 0
	serverHealthState.Unlock()
	if charged {
		t.Fatal("per-credential quota penalized the whole relay")
	}
	t.Logf("next allocation: %v", err)
	_, _, _, _, _, err = dialAndAllocate(ctx2, &stream{}, "user", "pass", pc.LocalAddr().String(), WorkerGroupConfig{UseUDP: true})
	if _, ok := err.(*credentialRelayQuotaError); !ok {
		t.Fatalf("retry should stop before dialing: %v", err)
	}
	if server.AllocationCount() != 1 {
		t.Fatal("unexpected server allocation count")
	}

}
