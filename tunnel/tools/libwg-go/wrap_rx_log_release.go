//go:build !wgdebug

package main

// A constant removes both formatting and the log call from release binaries.
const debugWrapRX = false
