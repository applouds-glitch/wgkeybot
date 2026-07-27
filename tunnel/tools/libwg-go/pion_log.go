package main

import "github.com/pion/logging"

// pion never returns an error for a failed allocation Refresh or
// CreatePermission — it only logs one (internal/client/allocation.go:157,168).
// Those are the two failures that silently kill a relay: the writes keep
// succeeding while the relay stops forwarding, so the stream looks alive right
// up until the dead-stream detector tears it down 90s later with no clue as to
// why. pion's default factory writes to stderr, which Android discards, so
// today that diagnosis is simply unavailable.
//
// pionLogFactory routes pion's own logs into turnLog with the stream ID
// attached. Only Warn and above are forwarded: pion Tracef's on the per-packet
// path (client.go:789 formats the peer address for every inbound packet), so
// the lower levels stay no-ops that never format their arguments.
// Debug was forwarded too for one diagnostic build, to answer what lifetime VK
// grants an allocation (600s, refreshed by pion at half that) and whether it
// answers a stale nonce with 438 (which pion retries) or something else (which
// it would not). Both settled, so Debug is a no-op again: on 18 streams it was
// ~10 formatted lines every two minutes carrying nothing actionable.
type pionLogFactory struct{ streamID int }

func (f pionLogFactory) NewLogger(scope string) logging.LeveledLogger {
	return pionLogger{streamID: f.streamID, scope: scope}
}

type pionLogger struct {
	streamID int
	scope    string
}

func (l pionLogger) Trace(string)             {}
func (l pionLogger) Tracef(string, ...any)    {}
func (l pionLogger) Debug(string)             {}
func (l pionLogger) Debugf(string, ...any)    {}
func (l pionLogger) Info(string)              {}
func (l pionLogger) Infof(string, ...any)     {}
func (l pionLogger) Warn(msg string)          { l.log("WARN", "%s", msg) }
func (l pionLogger) Warnf(f string, a ...any) { l.log("WARN", f, a...) }
func (l pionLogger) Error(msg string)         { l.log("ERROR", "%s", msg) }
func (l pionLogger) Errorf(f string, a ...any) {
	l.log("ERROR", f, a...)
}

func (l pionLogger) log(level, format string, args ...any) {
	turnLog("[STREAM %d] pion/%s %s: "+format, append([]any{l.streamID, l.scope, level}, args...)...)
}
