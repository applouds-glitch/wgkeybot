/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 *
 * Stand-in for the NDK's <android/log.h>, used only when the package is built
 * for the host so that `go test` runs without an Android toolchain. It declares
 * exactly what this package uses and nothing else; the real header wins on any
 * android build, where this directory is not on the include path at all.
 */

#ifndef WGKEYBOT_HOSTSHIM_ANDROID_LOG_H
#define WGKEYBOT_HOSTSHIM_ANDROID_LOG_H

typedef enum android_LogPriority {
	ANDROID_LOG_UNKNOWN = 0,
	ANDROID_LOG_DEFAULT,
	ANDROID_LOG_VERBOSE,
	ANDROID_LOG_DEBUG,
	ANDROID_LOG_INFO,
	ANDROID_LOG_WARN,
	ANDROID_LOG_ERROR,
	ANDROID_LOG_FATAL,
	ANDROID_LOG_SILENT,
} android_LogPriority;

int __android_log_write(int prio, const char *tag, const char *text);

#endif /* WGKEYBOT_HOSTSHIM_ANDROID_LOG_H */
