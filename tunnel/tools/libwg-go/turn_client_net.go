/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"net"

	"github.com/pion/transport/v4/stdnet"
	"github.com/pion/turn/v5"
)

// newTURNClient uses the caller's already protected connection. Pion's default
// stdnet.NewNet enumerates interfaces through netlink and can fail with
// "route ip+net: netlinkrib: permission denied" on Android/HarmonyOS before
// sending any Allocate request. Our UDP relay allocation (over UDP or TCP)
// only needs address resolution from Net, not interface discovery. The zero
// value provides that without querying interfaces or opening another socket.
func newTURNClient(config *turn.ClientConfig) (*turn.Client, error) {
	config.Net = &stdnet.Net{}
	return turn.NewClient(config)
}

// The production TURN socket is connected and protected before Pion receives it.
type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
