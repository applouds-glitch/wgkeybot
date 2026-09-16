package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/pion/logging"
)

// pion never returns an error for a failed allocation Refresh, CreatePermission
// or ChannelBind — it only logs one (internal/client/allocation.go:157,168,
// internal/client/udp_conn.go:493). Those are the failures that silently kill a
// relay: the writes keep succeeding while the relay stops forwarding, so the
// stream looks alive right up until the dead-stream detector tears it down 90s
// later with no clue as to why. pion's default factory writes to stderr, which
// Android discards, so without this factory the diagnosis is unavailable — and
// with permWatch attached these lines are not just diagnosis but the signal the
// stream is recycled on (see turn_permwatch.go).
//
// pionLogFactory routes pion's own logs into turnLog with the stream ID
// attached. Warn and above are forwarded, plus fatal receive-loop failures that
// Pion logs at Debug. Trace/per-packet Debug arguments remain unformatted.
// Successful refreshes are still inspected to reset permWatch failure counters.
//
// watch is optional; a nil watcher turns every note into a no-op, which is what
// callers that only want logging get.
type pionLogFactory struct {
	streamID int
	watch    *permWatch
}

func (f pionLogFactory) NewLogger(scope string) logging.LeveledLogger {
	l := pionLogger{streamID: f.streamID, scope: scope}
	// Only pion/turn's own client scope carries the allocation/binding
	// lifecycle markers; anything else sharing this factory must not be able
	// to trip the detector.
	if scope == permWatchScope {
		l.watch = f.watch
	}
	return l
}

type pionLogger struct {
	streamID int
	scope    string
	watch    *permWatch
}

func (l pionLogger) Trace(string)          {}
func (l pionLogger) Tracef(string, ...any) {}

const (
	pionReadLoopFailed = "Failed to read: %s. Exiting loop"
	pionInboundFailed  = "Failed to handle inbound message: %s. Exiting loop"
)

func (l pionLogger) Debug(msg string) { l.watch.note(msg) }
func (l pionLogger) Debugf(f string, args ...any) {
	l.watch.note(f)
	if l.scope == permWatchScope && pionReceiveFailure(f, args...) {
		l.log("WARN", f, args...)
	}
}

// A closed socket is expected during cancellation/teardown. Other read errors
// and malformed inbound packets stop Pion's reader and must not be hidden behind
// the later Allocate/Refresh timeout. Match exact formats, never arbitrary data.
func pionReceiveFailure(format string, args ...any) bool {
	if format != pionReadLoopFailed && format != pionInboundFailed {
		return false
	}
	if format == pionReadLoopFailed && len(args) > 0 {
		if err, ok := args[0].(error); ok && errors.Is(err, net.ErrClosed) {
			return false
		}
	}
	return true
}

func (l pionLogger) Info(string)          {}
func (l pionLogger) Infof(string, ...any) {}

func (l pionLogger) Warn(msg string) {
	l.watch.note(msg)
	l.log("WARN", "%s", msg)
}

// Warnf formats once and hands the same string to both the watcher and the log:
// the failure markers reach permWatch with pion's real error text attached, so
// the reason it latches still classifies through classifyCredError. Warn is a
// cold path (refresh cadence, not per packet), so the extra Sprintf is free.
func (l pionLogger) Warnf(f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	l.watch.note(msg)
	l.log("WARN", "%s", msg)
}

func (l pionLogger) Error(msg string) { l.log("ERROR", "%s", msg) }
func (l pionLogger) Errorf(f string, a ...any) {
	l.log("ERROR", f, a...)
}

func (l pionLogger) log(level, format string, args ...any) {
	turnLog("[STREAM %d] pion/%s %s: "+format, append([]any{l.streamID, l.scope, level}, args...)...)
}
