/* SPDX-License-Identifier: Apache-2.0 */

package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"github.com/pion/turn/v5"
)

// Use real framed TCP: an unrelated response must not overwrite the actual
// initial Allocate refusal. Both replies deliberately omit challenge attrs.
func TestInitialAllocateErrorMatchesTransactionOverTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	defer resetAllocationMismatchPauses()
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		pc := turn.NewSTUNConn(conn)
		buf := make([]byte, 2048)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			done <- err
			return
		}
		request := &stun.Message{Raw: buf[:n]}
		if err = request.Decode(); err != nil {
			done <- err
			return
		}
		wrongID := request.TransactionID
		wrongID[0] ^= 0xff
		for _, spec := range []struct {
			id   [stun.TransactionIDSize]byte
			code stun.ErrorCode
		}{
			{wrongID, stun.CodeAllocQuotaReached}, {request.TransactionID, stun.CodeAllocMismatch},
		} {
			response := stun.MustBuild(stun.NewTransactionIDSetter(spec.id), stun.NewType(stun.MethodAllocate, stun.ClassErrorResponse), stun.ErrorCodeAttribute{Code: spec.code}, stun.Fingerprint)
			if _, err = pc.WriteTo(response.Raw, conn.RemoteAddr()); err != nil {
				done <- err
				return
			}
		}
		// Keep the server socket open until the client has handled its response.
		pc.ReadFrom(buf)
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _, _, _, err = dialAndAllocateOnce(ctx, &stream{}, t.Name(), "pass", l.Addr().String(), WorkerGroupConfig{}, make(map[string]bool))
	if code, ok := turnErrorCode(err); !ok || code != stun.CodeAllocMismatch {
		t.Fatalf("unrelated transaction replaced actual 437: %v", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAllocateResponseDoesNotReplaceTransportErrors(t *testing.T) {
	c := &allocateResponseConn{refusal: turnErr(stun.CodeAllocMismatch).(*stun.TurnError)}
	for _, original := range []error{nil, context.Canceled, net.ErrClosed, errors.New("all retransmissions failed"), turnErr(stun.CodeForbidden)} {
		if got := c.allocationError(original); got != original {
			t.Fatalf("replaced %v with %v", original, got)
		}
	}
}
