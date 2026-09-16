/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// Exercise the real Pion client with an empty interface inventory, including
// authentication, allocation, permission creation and data in both directions.
// These tests run on a host without the Android JNI layer:
// go test turn_client_net.go turn_allocate_response.go turn_client_net_test.go
func TestTURNClientWithoutInterfaceDiscovery(t *testing.T) {
	for _, network := range []string{"udp4", "tcp4", "udp6", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1"
			if network[3] == '6' {
				host = "::1"
				// CI containers and some dev hosts have no IPv6 loopback; that
				// says nothing about the client under test.
				probe, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skipf("no IPv6 loopback: %v", err)
				}
				probe.Close()
			}
			listenAddr := net.JoinHostPort(host, "0")
			generator := &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP(host), Address: host,
			}
			serverConfig := turn.ServerConfig{
				Realm: "net-test",
				AuthHandler: func(a *turn.RequestAttributes) (string, []byte, bool) {
					return a.Username, turn.GenerateAuthKey(a.Username, "net-test", "pass"), true
				},
			}
			var addr string
			if network[:3] == "udp" {
				pc, err := net.ListenPacket(network, listenAddr)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { pc.Close() })
				addr = pc.LocalAddr().String()
				serverConfig.PacketConnConfigs = []turn.PacketConnConfig{{PacketConn: pc, RelayAddressGenerator: generator}}
			} else {
				listener, err := net.Listen(network, listenAddr)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				addr = listener.Addr().String()
				serverConfig.ListenerConfigs = []turn.ListenerConfig{{Listener: listener, RelayAddressGenerator: generator}}
			}
			server, err := turn.NewServer(serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { server.Close() })

			for attempt := 0; attempt < 2; attempt++ {
				t.Run(fmt.Sprintf("session%d", attempt), func(t *testing.T) {
					exerciseTURNClient(t, network, addr, listenAddr, server)
				})
			}
		})
	}
}

func exerciseTURNClient(t *testing.T, network, addr, listenAddr string, server *turn.Server) {
	t.Helper()
	var conn net.PacketConn
	raw, err := net.DialTimeout(network, addr, time.Second)
	if err == nil {
		if network[:3] == "udp" {
			conn = &connectedUDPConn{raw.(*net.UDPConn)}
		} else {
			conn = turn.NewSTUNConn(raw)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	responses := &allocateResponseConn{PacketConn: conn, remote: raw.RemoteAddr().String()}
	config := &turn.ClientConfig{Conn: responses, STUNServerAddr: addr, TURNServerAddr: addr, Username: "user", Password: "pass"}
	client, err := newTURNClient(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	interfaces, err := config.Net.Interfaces()
	if err != nil || len(interfaces) != 0 {
		t.Fatalf("client must not discover system interfaces: interfaces=%v err=%v", interfaces, err)
	}
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	relay, err := client.Allocate()
	err = responses.allocationError(err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	peer, err := net.ListenPacket("udp"+network[3:], listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := relay.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.WriteTo([]byte("request"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, source, err := peer.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "request" {
		t.Fatalf("unexpected outbound data: %q", buf[:n])
	}
	if _, err := peer.WriteTo([]byte("response"), source); err != nil {
		t.Fatal(err)
	}
	n, _, err = relay.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "response" {
		t.Fatalf("unexpected inbound data: %q", buf[:n])
	}
	// Exercise another permission transaction on the established client.
	if err := client.CreatePermission(peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if err := relay.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for server.AllocationCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("allocation was not released before reconnect")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTURNClientResolvesAddressesLikeDefaultNet(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	for _, addr := range []string{"127.0.0.1:3478", "[::1]:3478", "localhost:3478", "[fe80::1%wlan0]:3478"} {
		t.Run(addr, func(t *testing.T) {
			expected, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			client, err := newTURNClient(&turn.ClientConfig{Conn: conn, TURNServerAddr: addr, STUNServerAddr: addr})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			for _, resolved := range []net.Addr{client.TURNServerAddr(), client.STUNServerAddr()} {
				if resolved.String() != expected.String() {
					t.Fatalf("resolved %q, want %q", resolved, expected)
				}
			}
		})
	}
}
