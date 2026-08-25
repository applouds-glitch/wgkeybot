//go:build !android

/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package main

// Host build support, so `go test ./...` runs on a developer machine without an
// Android NDK.
//
// The package is cgo-bound to Android in two ways: it includes <android/log.h>,
// and it calls back into the JNI layer in jni.c (socket protection, the captcha
// dialog, the fatal-error notification). Neither exists off-device, so the whole
// package — every pure-Go unit test in it included — used to be unbuildable
// anywhere but in the NDK cross-build.
//
// This file supplies the include path for the header stand-in; host_shim.c
// supplies the C symbols, and jni.c is android-only. Nothing here is compiled
// into the shipped library: the android build takes the real header, the real
// -llog and the real jni.c, exactly as before.

/*
#cgo CFLAGS: -I${SRCDIR}/hostshim
*/
import "C"
