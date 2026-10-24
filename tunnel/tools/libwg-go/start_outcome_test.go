/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"net"
	"testing"
)

func TestStartTimeoutCode(t *testing.T) {
	cases := []struct {
		name          string
		credsObtained bool
		vkHeard       bool
		want          int32
	}{
		// Field log 12.10: no internet, every VK address reset before a byte came back.
		{"no creds, VK silent", false, false, startVKUnreachable},
		// VK answered (a captcha, an error_code): its refusal, not the network's.
		{"no creds, VK answered", false, true, -1},
		// Credentials in hand, relays silent: the relays' problem, not VK's.
		{"creds, VK silent", true, false, -1},
		{"creds, VK answered", true, true, -1},
	}
	for _, c := range cases {
		if got := startTimeoutCode(c.credsObtained, c.vkHeard); got != c.want {
			t.Errorf("%s: startTimeoutCode = %d, want %d", c.name, got, c.want)
		}
	}
}

// vkConnsHeard moves once per connection that carried a byte back, and not at
// all for one that closed silent — the reset in front of VK.
func TestHeardConnCountsConnectionsThatAnswered(t *testing.T) {
	read := func(answer bool) {
		client, server := net.Pipe()
		conn := &heardConn{Conn: client, onSilent: func() {}}
		go func() {
			if answer {
				server.Write([]byte("hello"))
				server.Write([]byte("again"))
			}
			server.Close()
		}()
		buf := make([]byte, 2)
		for {
			if _, err := conn.Read(buf); err != nil {
				break
			}
		}
		conn.Close()
	}

	before := vkConnsHeard.Load()
	read(false)
	if got := vkConnsHeard.Load() - before; got != 0 {
		t.Fatalf("silent connection counted as heard: +%d", got)
	}
	read(true)
	if got := vkConnsHeard.Load() - before; got != 1 {
		t.Fatalf("answering connection read in several chunks: +%d, want +1", got)
	}
}

// Field log 23.10: every resolver silent for the whole prefetch. Only when every
// group failed on our own network, with no credential and not a byte from VK,
// is the start's answer known before the groups run.
func TestPrefetchOutcomeCode(t *testing.T) {
	cases := []struct {
		name           string
		groups, ownNet int
		credsObtained  bool
		vkHeard        bool
		networkMoved   bool
		want           int32
	}{
		{"every group on a silent network", 2, 2, false, false, false, startVKUnreachable},
		{"one group failed otherwise", 2, 1, false, false, false, 0},
		{"a credential reached the start", 1, 1, true, false, false, 0},
		{"VK answered somewhere", 1, 1, false, true, false, 0},
		{"the network changed during the prefetch", 1, 1, false, false, true, 0},
		{"no groups", 0, 0, false, false, false, 0},
	}
	for _, c := range cases {
		if got := prefetchOutcomeCode(c.groups, c.ownNet, c.credsObtained, c.vkHeard, c.networkMoved); got != c.want {
			t.Errorf("%s: prefetchOutcomeCode = %d, want %d", c.name, got, c.want)
		}
	}
}
