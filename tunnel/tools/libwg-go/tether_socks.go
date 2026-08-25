/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	socksVersion5 = 0x05

	socksAuthNone         = 0x00
	socksAuthUnacceptable = 0xff

	socksCmdConnect = 0x01

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksRepSuccess          = 0x00
	socksRepGeneralFailure   = 0x01
	socksRepHostUnreachable  = 0x04
	socksRepCmdNotSupported  = 0x07
	socksRepAddrNotSupported = 0x08
)

// serveSocks5 implements just enough of RFC 1928 for a proxy client: no
// authentication (the access point is WPA2-protected and we listen only on its
// interface) and CONNECT only.
func (p *tetherProxy) serveSocks5(ctx context.Context, c net.Conn, br *bufio.Reader) {
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(br, greeting); err != nil {
		return
	}
	if greeting[0] != socksVersion5 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if bytes.IndexByte(methods, socksAuthNone) < 0 {
		// The client offered only methods we do not implement — typically someone
		// who typed credentials into their SOCKS settings, so the client insists
		// on username/password. RFC 1928 wants 0xFF and a close; replying 0x00
		// anyway left that client waiting for an auth exchange that never came,
		// which reads as a hang rather than a misconfiguration.
		turnLog("[TETHER] socks client from %s offered no acceptable auth method (%v)", c.RemoteAddr(), methods)
		_, _ = c.Write([]byte{socksVersion5, socksAuthUnacceptable})
		return
	}
	if _, err := c.Write([]byte{socksVersion5, socksAuthNone}); err != nil {
		return
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	if header[0] != socksVersion5 {
		return
	}
	host, err := readSocksAddr(br, header[3])
	if err != nil {
		socksReply(c, socksRepAddrNotSupported)
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	if header[1] != socksCmdConnect {
		// BIND and UDP ASSOCIATE are stage-two territory: the transparent Android
		// client will need UDP, nothing in this version does. Refusing plainly
		// lets a client fall back to TCP instead of waiting for a timeout.
		turnLog("[TETHER] socks command 0x%02x not supported", header[1])
		socksReply(c, socksRepCmdNotSupported)
		return
	}

	upstream, err := p.dialUpstream(ctx, c, host, port)
	if err != nil {
		turnLog("[TETHER] socks connect %s:%d failed: %v", host, port, err)
		socksReply(c, socksRepHostUnreachable)
		return
	}
	defer p.releaseConn(upstream)

	if err := socksReply(c, socksRepSuccess); err != nil {
		return
	}
	p.splice(c, br, upstream)
}

func readSocksAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypDomain:
		length := make([]byte, 1)
		if _, err := io.ReadFull(br, length); err != nil {
			return "", err
		}
		buf := make([]byte, int(length[0]))
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	}
	return "", fmt.Errorf("unsupported address type 0x%02x", atyp)
}

// socksReply answers with a zero bound address: clients ignore it for CONNECT,
// and we have nothing meaningful to report.
func socksReply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{socksVersion5, code, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
