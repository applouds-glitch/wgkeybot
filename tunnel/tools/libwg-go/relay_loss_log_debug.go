//go:build wgdebug

package main

import "fmt"

// relayLossLogEvery: every window. A bench reads the loss per relay against
// the download's seconds, and on 2026-11-07 the 45-55 s cells ended before the
// minute's line came — the hotspot run had no per-relay loss at all, and the
// LTE run only the windows above relayLossLogAbove. Debug builds only: one
// line per 10 s is noise in a user's journal.
const relayLossLogEvery = 1

// relayLossLogMinPackets: every window with any traffic is printed (see the
// release build's).
const relayLossLogMinPackets = 1

// relayOrderLogPairs: the [RELAY ORDER] line names which relay overtook which.
const relayOrderLogPairs = true

// relayLossHolesNote: in how many gaps a relay's lost packets came, at the end of
// its part of the [RELAY LOSS] line. The judges' chance bound takes each lost
// packet for an event of its own, and the book charges a relay with a whole gap
// at once — up to seven packets (placeGapLocked). The average length of a gap
// under load says whether that bound holds (audit, 2026-11-10: equal relays
// losing in runs of about two drew false rests in simulation). Inside the
// brackets, so that the benches' "% of N" patterns read the line as before.
func relayLossHolesNote(s relayLossSample) string {
	if s.lost == 0 {
		return ""
	}
	return fmt.Sprintf(", lost in %d holes", s.holes)
}
