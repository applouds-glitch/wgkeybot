/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

//go:build !android

/*
 * Host stand-ins for the C symbols the package links against on Android: one
 * from liblog, the rest from jni.c (which is android-only, since it needs a
 * JVM). See host_shim.go.
 *
 * These exist to make the package link off-device, not to emulate Android. Code
 * under test that reaches one of them gets an honest inert answer — no socket
 * is protected, no captcha dialog appears — so a test that depends on Android
 * behaviour must fake it at the Go level instead.
 */

#include <stdio.h>
#include <stdlib.h>

int __android_log_write(int prio, const char *tag, const char *text)
{
	(void)prio;
	fprintf(stderr, "[%s] %s\n", tag ? tag : "?", text ? text : "");
	return 1;
}

/* There is no VpnService here, so nothing needs protecting — and reporting
 * success keeps the dial paths under test on their normal course. */
int wgProtectSocket(int fd)
{
	(void)fd;
	return 0;
}

/* Same, minus the bindSocket half. On device this is what the internet-sharing
 * listener uses so its socket never gets the physical network's mark; here both
 * are equally inert. */
int wgProtectSocketNoBind(int fd)
{
	(void)fd;
	return 0;
}

/* The direct-route variant (protect + bind, quiet). Equally inert here. */
int wgProtectSocketDirect(int fd)
{
	(void)fd;
	return 0;
}

/* NULL reads as "the platform told us nothing", which every caller of these
 * already handles: no system DNS servers, no captcha token, no device profile. */
const char *getNetworkDnsServers(long long network_handle)
{
	(void)network_handle;
	return NULL;
}

const char *requestCaptcha(const char *redirect_uri, int visible)
{
	(void)redirect_uri;
	(void)visible;
	return NULL;
}

void cancelCaptcha(void)
{
}

void burnCaptchaPersona(const char *reason)
{
	(void)reason;
}

const char *getCaptchaDeviceProfile(void)
{
	return NULL;
}

void notifyTurnFatal(const char *reason)
{
	(void)reason;
}

void notifyTetherStopped(const char *reason)
{
	(void)reason;
}
