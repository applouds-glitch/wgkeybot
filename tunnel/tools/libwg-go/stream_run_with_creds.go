/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// runWithCreds establishes one TURN session with pre-fetched credentials.
// Retry and credential rotation are managed by the calling WorkerGroup.
func (s *stream) runWithCreds(ctx context.Context, user, pass, addr string, cfg WorkerGroupConfig) error {
	s.ready.Store(false)
	turnLog("[STREAM %d] Dial TURN %s (group %d)", s.id, addr, cfg.GroupID)

	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
		Control: protectControl,
	}

	var turnConn net.PacketConn
	if cfg.UseUDP {
		c, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return fmt.Errorf("TURN UDP dial: %w", err)
		}
		defer c.Close()
		turnConn = &connectedUDPConn{c.(*net.UDPConn)}
	} else {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("TURN TCP dial: %w", err)
		}
		defer c.Close()
		turnConn = turn.NewSTUNConn(c)
	}

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: addr,
		TURNServerAddr: addr,
		Username:       user,
		Password:       pass,
		Conn:           turnConn,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return fmt.Errorf("TURN client: %w", err)
	}
	defer client.Close()

	if err := client.Listen(); err != nil {
		return fmt.Errorf("TURN listen: %w", err)
	}

	relayConn, err := client.Allocate()
	if err != nil {
		return fmt.Errorf("TURN allocate: %w", err)
	}
	defer relayConn.Close()

	turnLog("[STREAM %d] Relay: %s", s.id, relayConn.LocalAddr())

	switch cfg.PeerType {
	case "wireguard":
		return s.runNoDTLS(ctx, relayConn, cfg.PeerAddr)
	default:
		return s.runDTLS(ctx, relayConn, cfg.PeerAddr, true)
	}
}
