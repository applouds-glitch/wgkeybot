//go:build !wgdebug

package main

// relayLossLogEvery: one routine [RELAY LOSS] line per six windows (a minute),
// enough for a field journal to show what each relay carried and lost.
const relayLossLogEvery = 6

// relayLossLogMinPackets: the routine [RELAY LOSS] and [RELAY ORDER] lines of a
// window that carried fewer packets are left out. An idle tunnel's minute is a
// handful of them — "0.0% of 3 (4 streams, 0/s each)", "4 packets, 0.00% late"
// (2026-11-13) — which says nothing, and it said it twice a minute for as long
// as the VPN was up. The loss judge does not read a relay below as much either
// (relayJudgeMinPackets); a window with a relay that lost above
// relayLossLogAbove of relayJudgeMinPackets or more of its own is printed all
// the same (anyRelayLossAbove).
const relayLossLogMinPackets = relayJudgeMinPackets

// relayOrderLogPairs: the [RELAY ORDER] line leaves out which relay overtook
// which — the longest part of it, read by the benches. How late each relay's
// packets came stays.
const relayOrderLogPairs = false

// relayLossHolesNote: nothing in a release journal (see the debug build's).
func relayLossHolesNote(relayLossSample) string { return "" }
