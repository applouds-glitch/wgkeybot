/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestPionReceiveFailuresStayVisible(t *testing.T) {
	for _, tc := range []struct {
		format string
		err    error
		want   bool
	}{
		{pionInboundFailed, errors.New("non-STUN message from STUN server"), true},
		{pionReadLoopFailed, io.EOF, true},
		{pionReadLoopFailed, errors.New("network unreachable"), true},
		{pionReadLoopFailed, &net.OpError{Op: "read", Net: "udp", Err: net.ErrClosed}, false},
		{"Received %s", fmt.Errorf("user payload: %s", pionInboundFailed), false},
	} {
		if got := pionReceiveFailure(tc.format, tc.err); got != tc.want {
			t.Errorf("%s / %v: got %v", tc.format, tc.err, got)
		}
	}
}
