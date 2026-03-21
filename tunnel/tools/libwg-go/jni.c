/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct go_string { const char *str; long n; };
extern int wgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings);
extern void wgTurnOff(int handle);
extern int wgGetSocketV4(int handle);
extern int wgGetSocketV6(int handle);
extern char *wgGetConfig(int handle);
extern char *wgVersion();
extern int wgTurnProxyStart(const char *peer_addr, const char *vklink, int n, int udp, const char *listen_addr, const char *turn_ip, int turn_port, int no_dtls);
extern void wgTurnProxyStop();
extern void wgNotifyNetworkChange();

static JavaVM *java_vm;
static jobject vpn_service_global;
static jmethodID protect_method;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	java_vm = vm;
	return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgSetVpnService(JNIEnv *env, jclass c, jobject vpn_service)
{
	if (vpn_service_global) {
		(*env)->DeleteGlobalRef(env, vpn_service_global);
		vpn_service_global = NULL;
		protect_method = NULL;
	}
	if (vpn_service) {
		vpn_service_global = (*env)->NewGlobalRef(env, vpn_service);
		jclass vpn_service_class = (*env)->GetObjectClass(env, vpn_service_global);
		protect_method = (*env)->GetMethodID(env, vpn_service_class, "protect", "(I)Z");
	}
}

int wgProtectSocket(int fd)
{
	JNIEnv *env;
	int ret = 0;
	int attached = 0;

	// Validate fd
	if (fd < 0) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocket: invalid fd=%d", fd);
		return -1;
	}

	if (!vpn_service_global || !protect_method) {
		__android_log_print(ANDROID_LOG_WARN, "WireGuard/JNI",
			"wgProtectSocket(fd=%d): vpn_service_global is NULL, SKIPPING", fd);
		return 0;
	}
	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"wgProtectSocket(fd=%d): AttachCurrentThread failed", fd);
			return -1;
		}
		attached = 1;
	}

	if ((*env)->CallBooleanMethod(env, vpn_service_global, protect_method, (jint)fd)) {
		__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI",
			"wgProtectSocket(fd=%d): SUCCESS", fd);
		ret = 0;
	} else {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocket(fd=%d): VpnService.protect() FAILED - tunnel not established yet?", fd);
		ret = -1;
	}
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return ret;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
	const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
	size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
	size_t settings_len = (*env)->GetStringUTFLength(env, settings);
	int ret = wgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_len
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_len
	});
	(*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
	(*env)->ReleaseStringUTFChars(env, settings, settings_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
	wgTurnOff(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
	return wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
	jstring ret;
	char *config = wgGetConfig(handle);
	if (!config)
		return NULL;
	ret = (*env)->NewStringUTF(env, config);
	free(config);
	return ret;
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
	jstring ret;
	char *version = wgVersion();
	if (!version)
		return NULL;
	ret = (*env)->NewStringUTF(env, version);
	free(version);
	return ret;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStart(JNIEnv *env, jclass c, jstring peer_addr, jstring vklink, jint n, jint useUdp, jstring listen_addr, jstring turn_ip, jint turn_port, jint no_dtls)
{
	const char *peer_addr_str = (*env)->GetStringUTFChars(env, peer_addr, 0);
	const char *vklink_str = (*env)->GetStringUTFChars(env, vklink, 0);
	const char *listen_addr_str = (*env)->GetStringUTFChars(env, listen_addr, 0);
	const char *turn_ip_str = (*env)->GetStringUTFChars(env, turn_ip, 0);
	int ret = wgTurnProxyStart(peer_addr_str, vklink_str, (int)n, (int)useUdp, listen_addr_str, turn_ip_str, (int)turn_port, (int)no_dtls);
	(*env)->ReleaseStringUTFChars(env, peer_addr, peer_addr_str);
	(*env)->ReleaseStringUTFChars(env, vklink, vklink_str);
	(*env)->ReleaseStringUTFChars(env, listen_addr, listen_addr_str);
	(*env)->ReleaseStringUTFChars(env, turn_ip, turn_ip_str);
	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgNotifyNetworkChange(JNIEnv *env, jclass c)
{
	wgNotifyNetworkChange();
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStop(JNIEnv *env, jclass c)
{
	wgTurnProxyStop();
}
