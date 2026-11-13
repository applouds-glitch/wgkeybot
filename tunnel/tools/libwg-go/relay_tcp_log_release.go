//go:build !wgdebug

package main

import "time"

// relaySocketRoutineLogEvery: windows in which traffic moved and nothing went
// wrong are summed into one [TCP] line a minute. Under load six lines a minute
// (2026-11-13) were most of what a release journal kept and said nothing the
// minute's sum does not; a window with a stall, a stream stalled now or a
// packet the dispatcher dropped or steered still prints after
// relaySocketLogInterval (relaySocketWatch.newsLocked).
const relaySocketRoutineLogEvery = time.Minute
