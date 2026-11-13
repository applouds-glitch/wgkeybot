//go:build wgdebug

package main

// relaySocketRoutineLogEvery: a [TCP] summary every window, as before. A bench
// reads the pool's rtt, backlog and the relay's window against the download's
// seconds.
const relaySocketRoutineLogEvery = relaySocketLogInterval
