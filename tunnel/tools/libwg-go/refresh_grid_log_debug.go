//go:build wgdebug

package main

// refreshGridLog: one line per allocation and permission refresh, saying
// whether the keepalive grid or the backstop sent it (refresh_grid.go). Debug
// builds only: ten streams make about five such lines a minute, twice what a
// release build writes in all on an idle tunnel.
const refreshGridLog = true
