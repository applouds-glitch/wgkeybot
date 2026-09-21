/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

/* Needs a JVM and the NDK sysroot, so it is android-only; host_shim.c stands in
 * for the symbols it exports when the package is built for tests. */
//go:build android

#include <jni.h>
#include <android/log.h>
#include <pthread.h>
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
extern int wgTurnProxyStart(const char *peer_addr, const char *vklink, const char *mode, int n, int udp, const char *listen_addr, const char *turn_ip, int turn_port, const char *peer_type, int streams_per_cred, int watchdog_timeout, const char *wrap_key);
extern void wgTurnProxyStop();
extern void wgTurnDropCredentials(void);
extern void wgSetSystemDns(const char *dns_servers);
extern void wgSetNetworkState(long long handle, int relay_transport);
extern int wgTurnReadyStreams(void);
extern int wgTetherStart(const char *bind_ip, int port, const char *dns_servers, const char *tunnel_addrs, const char *routing_dir, const char *direct_dns);
extern void wgTetherStop(void);
extern char *wgTetherStats(void);

static JavaVM *java_vm;
static jobject vpn_service_global;
static jmethodID protect_method;
static jmethodID get_system_service_method;
static jmethodID get_all_networks_method;
static jmethodID get_network_handle_method;
static jmethodID bind_socket_method;
static jfieldID file_descriptor_descriptor;
static jmethodID file_descriptor_init;
static jclass connectivity_manager_class_global;
static jclass network_class_global;
static jclass file_descriptor_class_global;
static jobject connectivity_manager_instance_global;
static jobject current_network_global = NULL;
static jlong current_network_handle = 0;

// Captcha handler
static jclass turn_backend_class_global = NULL;
static jmethodID on_captcha_required_method = NULL;
static jmethodID on_captcha_cancel_method = NULL;
static jmethodID on_captcha_persona_burn_method = NULL;
static jmethodID get_captcha_device_profile_method = NULL;
static jmethodID on_turn_fatal_method = NULL;
static jmethodID on_tether_stopped_method = NULL;

// Guards every global above. Go worker goroutines call wgProtectSocket from many
// threads for the whole life of the proxy, while a Java thread can delete those
// same global refs underneath them (wgSetVpnService(NULL) on stop, and the
// network ref on every WiFi↔cellular switch). Reading a deleted global ref makes
// ART abort the process, so readers snapshot what they need under this lock and
// keep the objects alive with local refs for the duration of the call.
//
// Never hold this across a Java call that can block for long (the captcha
// WebView blocks up to 120s): snapshot, unlock, then call.
static pthread_mutex_t jni_globals_mutex = PTHREAD_MUTEX_INITIALIZER;

// Replaces the cached physical Network. Caller must hold jni_globals_mutex.
//
// The Network arrives as the object the Android side already holds. It used to
// arrive as a handle, which this function resolved with a getAllNetworks() binder
// scan — run under this very mutex, so it stalled every wgProtectSocket in flight,
// on a path that fires during a handover, which is exactly when workers are
// dialing. The scan also had a failure mode of its own: a network that went away
// between the monitor seeing it and this call resolved to nothing, and the dials
// went out unbound with only a WARN to say so. Holding the object removes both,
// and removes the dependency on a registered ConnectivityManager: the cache is now
// correct even while no VpnService exists.
//
// The handle rides along for two things only — deduping, and naming the network in
// the log. Idempotent: this is where "did anything change?" is answered, so no
// caller has to keep a copy of the answer.
static void set_current_network_locked(JNIEnv *env, jobject network, jlong handle)
{
	if (!network)
		handle = 0;
	if (handle == current_network_handle && (handle == 0 || current_network_global))
		return;

	if (current_network_global) {
		(*env)->DeleteGlobalRef(env, current_network_global);
		current_network_global = NULL;
	}
	current_network_handle = handle;

	if (network)
		current_network_global = (*env)->NewGlobalRef(env, network);

	__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI",
		"wgSetNetwork: dials now bind to net %lld%s", (long long)handle,
		current_network_global ? "" : " (none: protected but unbound)");
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	java_vm = vm;
	return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgSetVpnService(JNIEnv *env, jclass c, jobject vpn_service)
{
	pthread_mutex_lock(&jni_globals_mutex);
	if (vpn_service_global) {
		(*env)->DeleteGlobalRef(env, vpn_service_global);
		vpn_service_global = NULL;
		protect_method = NULL;
		get_system_service_method = NULL;
		get_all_networks_method = NULL;
		get_network_handle_method = NULL;
		bind_socket_method = NULL;
		file_descriptor_descriptor = NULL;
		file_descriptor_init = NULL;
		if (connectivity_manager_class_global) (*env)->DeleteGlobalRef(env, connectivity_manager_class_global);
		if (network_class_global) (*env)->DeleteGlobalRef(env, network_class_global);
		if (file_descriptor_class_global) (*env)->DeleteGlobalRef(env, file_descriptor_class_global);
		if (connectivity_manager_instance_global) (*env)->DeleteGlobalRef(env, connectivity_manager_instance_global);
		connectivity_manager_class_global = NULL;
		network_class_global = NULL;
		file_descriptor_class_global = NULL;
		connectivity_manager_instance_global = NULL;
		// NOTE: current_network_global/_handle are deliberately left alone. The
		// Network describes the device's connectivity, not this VpnService, and
		// nothing about it needs re-registering — so it stays valid across a
		// teardown instead of having to be resolved again afterwards.
		// NOTE: Do NOT reset turn_backend_class_global / on_captcha_required_method here.
		// TurnBackend is a Java class independent of VpnService lifecycle.
	}
	if (vpn_service) {
		vpn_service_global = (*env)->NewGlobalRef(env, vpn_service);
		jclass vpn_service_class = (*env)->GetObjectClass(env, vpn_service_global);
		protect_method = (*env)->GetMethodID(env, vpn_service_class, "protect", "(I)Z");
		get_system_service_method = (*env)->GetMethodID(env, vpn_service_class, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");

		// Cache TurnBackend class and captcha method
		if (!turn_backend_class_global) {
			jclass tb_class = (*env)->FindClass(env, "com/wireguard/android/backend/TurnBackend");
			if (tb_class) {
				turn_backend_class_global = (*env)->NewGlobalRef(env, tb_class);
				// A missing method (e.g. stripped by R8) leaves a pending
				// NoSuchMethodError; clear it or the next JNI call aborts the VM.
				on_captcha_required_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "onCaptchaRequired", "(Ljava/lang/String;Z)Ljava/lang/String;");
				if (!on_captcha_required_method) {
					(*env)->ExceptionClear(env);
					__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
						"wgSetVpnService: TurnBackend.onCaptchaRequired not found — captcha WebView disabled");
				}
				on_captcha_cancel_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "onCaptchaCancel", "()V");
				if (!on_captcha_cancel_method) {
					(*env)->ExceptionClear(env);
					__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
						"wgSetVpnService: TurnBackend.onCaptchaCancel not found — a captcha in progress cannot be aborted");
				}
				on_captcha_persona_burn_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "onCaptchaPersonaBurn", "(Ljava/lang/String;)V");
				if (!on_captcha_persona_burn_method) {
					(*env)->ExceptionClear(env);
					__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
						"wgSetVpnService: TurnBackend.onCaptchaPersonaBurn not found — a rejected device identity cannot be rotated");
				}
				on_turn_fatal_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "onTurnFatal", "(Ljava/lang/String;)V");
				if (!on_turn_fatal_method) {
					(*env)->ExceptionClear(env);
					__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
						"wgSetVpnService: TurnBackend.onTurnFatal not found — terminal TURN failures stay silent");
				}
				on_tether_stopped_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "onTetherStopped", "(Ljava/lang/String;)V");
				if (!on_tether_stopped_method) {
					(*env)->ExceptionClear(env);
					__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
						"wgSetVpnService: TurnBackend.onTetherStopped not found — a sharing proxy that retires itself stays 'Active' until the next stats poll");
				}
				get_captcha_device_profile_method = (*env)->GetStaticMethodID(env, turn_backend_class_global, "getCaptchaDeviceProfile", "()Ljava/lang/String;");
				if (!get_captcha_device_profile_method) {
					(*env)->ExceptionClear(env);
					__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
						"wgSetVpnService: TurnBackend.getCaptchaDeviceProfile not found — using fallback captcha profile");
				}
				(*env)->DeleteLocalRef(env, tb_class);
			}
		}

		jclass cm_class = (*env)->FindClass(env, "android/net/ConnectivityManager");
		connectivity_manager_class_global = (*env)->NewGlobalRef(env, cm_class);
		get_all_networks_method = (*env)->GetMethodID(env, connectivity_manager_class_global, "getAllNetworks", "()[Landroid/net/Network;");

		jclass n_class = (*env)->FindClass(env, "android/net/Network");
		network_class_global = (*env)->NewGlobalRef(env, n_class);
		get_network_handle_method = (*env)->GetMethodID(env, network_class_global, "getNetworkHandle", "()J");
		bind_socket_method = (*env)->GetMethodID(env, network_class_global, "bindSocket", "(Ljava/io/FileDescriptor;)V");

		jclass fd_class = (*env)->FindClass(env, "java/io/FileDescriptor");
		file_descriptor_class_global = (*env)->NewGlobalRef(env, fd_class);
		file_descriptor_init = (*env)->GetMethodID(env, file_descriptor_class_global, "<init>", "()V");
		file_descriptor_descriptor = (*env)->GetFieldID(env, file_descriptor_class_global, "descriptor", "I");

		jstring cm_service_name = (*env)->NewStringUTF(env, "connectivity");
		jobject cm_obj = (*env)->CallObjectMethod(env, vpn_service_global, get_system_service_method, cm_service_name);
		if (cm_obj) {
			connectivity_manager_instance_global = (*env)->NewGlobalRef(env, cm_obj);
			(*env)->DeleteLocalRef(env, cm_obj);
		}
		(*env)->DeleteLocalRef(env, cm_service_name);
	}
	pthread_mutex_unlock(&jni_globals_mutex);
}

// protect_and_bind is the body shared by wgProtectSocket and
// wgProtectSocketDirect: VpnService.protect(), then Network.bindSocket() to the
// cached physical network. who names the caller in log lines; quiet drops the
// success line, which the TURN dials want (a handful per session, and the
// bound netId is a useful fact) and the sharing proxy's direct dials cannot
// afford (one per connection a tethered client opens).
static int protect_and_bind(int fd, const char *who, int quiet)
{
	JNIEnv *env;
	int ret = 0;
	int attached = 0;

	// Validate fd
	if (fd < 0) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"%s: invalid fd=%d", who, fd);
		return -1;
	}

	pthread_mutex_lock(&jni_globals_mutex);
	int registered = vpn_service_global != NULL && protect_method != NULL;
	pthread_mutex_unlock(&jni_globals_mutex);
	if (!registered) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"%s(fd=%d): vpn_service_global is NULL! CANNOT PROTECT", who, fd);
		return -1;
	}
	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"%s(fd=%d): AttachCurrentThread failed", who, fd);
			return -1;
		}
		attached = 1;
	}

	// Snapshot everything this call needs. The local refs keep the objects alive
	// even if the Java side tears the globals down while we are calling into them.
	pthread_mutex_lock(&jni_globals_mutex);
	jobject vpn_service = vpn_service_global ? (*env)->NewLocalRef(env, vpn_service_global) : NULL;
	jobject network = current_network_global ? (*env)->NewLocalRef(env, current_network_global) : NULL;
	jclass fd_class = file_descriptor_class_global ? (jclass)(*env)->NewLocalRef(env, file_descriptor_class_global) : NULL;
	jmethodID protect = protect_method;
	jmethodID bind_socket = bind_socket_method;
	jmethodID fd_init = file_descriptor_init;
	jfieldID fd_field = file_descriptor_descriptor;
	jlong network_handle = current_network_handle;
	pthread_mutex_unlock(&jni_globals_mutex);

	if (!vpn_service || !protect) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"%s(fd=%d): VpnService went away mid-call! CANNOT PROTECT", who, fd);
		ret = -1;
		goto cleanup;
	}

	if ((*env)->CallBooleanMethod(env, vpn_service, protect, (jint)fd)) {
		// Use cached network object for immediate binding
		if (network && bind_socket && fd_class && fd_init && fd_field) {
			jobject fd_obj = (*env)->NewObject(env, fd_class, fd_init);
			(*env)->SetIntField(env, fd_obj, fd_field, fd);
			(*env)->CallVoidMethod(env, network, bind_socket, fd_obj);
			if ((*env)->ExceptionCheck(env)) {
				__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI", "%s(fd=%d): bindSocket exception!", who, fd);
				(*env)->ExceptionClear(env);
			} else if (!quiet) {
				__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "%s(fd=%d): SUCCESS (protected + bound to net %lld)", who, fd, (long long)network_handle);
			}
			(*env)->DeleteLocalRef(env, fd_obj);
		} else if (!quiet) {
			__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI", "%s(fd=%d): SUCCESS (protected, but NOT bound - handle=%lld)", who, fd, (long long)network_handle);
		}
		ret = 0;
	} else {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"%s(fd=%d): VpnService.protect() FAILED", who, fd);
		ret = -1;
	}
cleanup:
	if (vpn_service) (*env)->DeleteLocalRef(env, vpn_service);
	if (network) (*env)->DeleteLocalRef(env, network);
	if (fd_class) (*env)->DeleteLocalRef(env, fd_class);
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return ret;
}

int wgProtectSocket(int fd)
{
	return protect_and_bind(fd, "wgProtectSocket", 0);
}

// wgProtectSocketDirect is wgProtectSocket for the sharing proxy's direct
// route (tether_route.go): a tethered client's connection that the routing
// profile sends past the tunnel. Same protect, same bind to the physical
// network — that is exactly what makes the socket leave over the uplink — but
// silent on success, because it runs once per such connection and once per
// direct DNS query.
int wgProtectSocketDirect(int fd)
{
	return protect_and_bind(fd, "wgProtectSocketDirect", 1);
}

// wgProtectSocketNoBind is wgProtectSocket without the bindSocket half: it keeps
// the socket out of the tun and stops there.
//
// The bind above is right for every TURN dial — those must leave over the
// physical uplink, so stamping them with its netId is the whole point. It is
// wrong for the internet-sharing listener. Binding to a network installs an
// explicit-network routing rule, and that rule outranks the local-network rule
// for the access point's own subnet, so replies to a tethered client would be
// sent out the mobile interface carrying a 192.168.x.1 source address and never
// reach the client. Accepted sockets inherit the listener's mark and cannot be
// scrubbed afterwards (bindSocket throws on a connected socket), so the fix has
// to be to never set the mark in the first place.
//
// Keep the two functions separate. Unifying them re-breaks one caller or the
// other.
int wgProtectSocketNoBind(int fd)
{
	JNIEnv *env;
	int ret = 0;
	int attached = 0;

	// Validate fd
	if (fd < 0) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocketNoBind: invalid fd=%d", fd);
		return -1;
	}

	pthread_mutex_lock(&jni_globals_mutex);
	int registered = vpn_service_global != NULL && protect_method != NULL;
	pthread_mutex_unlock(&jni_globals_mutex);
	if (!registered) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocketNoBind(fd=%d): vpn_service_global is NULL! CANNOT PROTECT", fd);
		return -1;
	}
	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"wgProtectSocketNoBind(fd=%d): AttachCurrentThread failed", fd);
			return -1;
		}
		attached = 1;
	}

	// Snapshot everything this call needs. The local refs keep the objects alive
	// even if the Java side tears the globals down while we are calling into them.
	pthread_mutex_lock(&jni_globals_mutex);
	jobject vpn_service = vpn_service_global ? (*env)->NewLocalRef(env, vpn_service_global) : NULL;
	jmethodID protect = protect_method;
	pthread_mutex_unlock(&jni_globals_mutex);

	if (!vpn_service || !protect) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocketNoBind(fd=%d): VpnService went away mid-call! CANNOT PROTECT", fd);
		ret = -1;
		goto cleanup_nobind;
	}

	if ((*env)->CallBooleanMethod(env, vpn_service, protect, (jint)fd)) {
		// Deliberately silent. Unlike wgProtectSocket, which runs a handful of
		// times for the TURN streams, this runs once per accepted tethered
		// connection: logging success here buried the actual diagnostics under
		// hundreds of identical lines the first time sharing carried real traffic.
		// Failure below still speaks up.
		ret = 0;
	} else {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"wgProtectSocketNoBind(fd=%d): VpnService.protect() FAILED", fd);
		ret = -1;
	}
cleanup_nobind:
	if (vpn_service) (*env)->DeleteLocalRef(env, vpn_service);
	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
	return ret;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
	const char *ifname_jni = (*env)->GetStringUTFChars(env, ifname, 0);
	const char *settings_jni = (*env)->GetStringUTFChars(env, settings, 0);

	// Duplicate strings to avoid MTE issues with JNI-tagged pointers during Go execution
	char *ifname_str = ifname_jni ? strdup(ifname_jni) : NULL;
	char *settings_str = settings_jni ? strdup(settings_jni) : NULL;

	int ret = wgTurnOn((struct go_string){
		.str = ifname_str,
		.n = ifname_str ? (long)strlen(ifname_str) : 0
	}, tun_fd, (struct go_string){
		.str = settings_str,
		.n = settings_str ? (long)strlen(settings_str) : 0
	});

	(*env)->ReleaseStringUTFChars(env, ifname, ifname_jni);
	(*env)->ReleaseStringUTFChars(env, settings, settings_jni);

	free(ifname_str);
	free(settings_str);

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

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStart(JNIEnv *env, jclass c, jstring peer_addr, jstring vklink, jstring mode, jint n, jint useUdp, jstring listen_addr, jstring turn_ip, jint turn_port, jstring peer_type, jint streams_per_cred, jint watchdog_timeout, jstring wrap_key)
{
	const char *peer_addr_jni = (*env)->GetStringUTFChars(env, peer_addr, 0);
	const char *vklink_jni = (*env)->GetStringUTFChars(env, vklink, 0);
	const char *mode_jni = (*env)->GetStringUTFChars(env, mode, 0);
	const char *listen_addr_jni = (*env)->GetStringUTFChars(env, listen_addr, 0);
	const char *turn_ip_jni = (*env)->GetStringUTFChars(env, turn_ip, 0);
	const char *peer_type_jni = (*env)->GetStringUTFChars(env, peer_type, 0);
    const char *wrap_key_jni = wrap_key ? (*env)->GetStringUTFChars(env, wrap_key, 0) : NULL;
    char *wrap_key_str = wrap_key_jni ? strdup(wrap_key_jni) : NULL;

	// Duplicate strings to avoid MTE issues with JNI-tagged pointers during Go execution
	char *peer_addr_str = peer_addr_jni ? strdup(peer_addr_jni) : NULL;
	char *vklink_str = vklink_jni ? strdup(vklink_jni) : NULL;
	char *mode_str = mode_jni ? strdup(mode_jni) : NULL;
	char *listen_addr_str = listen_addr_jni ? strdup(listen_addr_jni) : NULL;
	char *turn_ip_str = turn_ip_jni ? strdup(turn_ip_jni) : NULL;
	char *peer_type_str = peer_type_jni ? strdup(peer_type_jni) : NULL;

	// Nothing about the physical network is passed or stamped here. A start can
	// spend minutes in its caller's retry loop (captcha ladder, stream-count
	// fallbacks), so anything it carried would be whatever was current when the
	// loop began — and applying that on every attempt put the dialer, and the
	// resolver, back on the network the session started on. Both follow
	// wgSetNetwork() instead.
	int ret = wgTurnProxyStart(peer_addr_str, vklink_str, mode_str, (int)n, (int)useUdp, listen_addr_str, turn_ip_str, (int)turn_port, peer_type_str, (int)streams_per_cred, (int)watchdog_timeout,wrap_key_str);

	(*env)->ReleaseStringUTFChars(env, peer_addr, peer_addr_jni);
	(*env)->ReleaseStringUTFChars(env, vklink, vklink_jni);
	(*env)->ReleaseStringUTFChars(env, mode, mode_jni);
	(*env)->ReleaseStringUTFChars(env, listen_addr, listen_addr_jni);
	(*env)->ReleaseStringUTFChars(env, turn_ip, turn_ip_jni);
	(*env)->ReleaseStringUTFChars(env, peer_type, peer_type_jni);
    if (wrap_key_jni) (*env)->ReleaseStringUTFChars(env, wrap_key, wrap_key_jni);
    free(wrap_key_str);

	free(peer_addr_str);
	free(vklink_str);
	free(mode_str);
	free(listen_addr_str);
	free(turn_ip_str);
	free(peer_type_str);

	return ret;
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTetherStart(JNIEnv *env, jclass c, jstring bind_ip, jint port, jstring dns_servers, jstring tunnel_addrs, jstring routing_dir, jstring direct_dns)
{
	const char *bind_ip_jni = (*env)->GetStringUTFChars(env, bind_ip, 0);
	const char *dns_jni = dns_servers ? (*env)->GetStringUTFChars(env, dns_servers, 0) : NULL;
	const char *tunnel_addrs_jni = tunnel_addrs ? (*env)->GetStringUTFChars(env, tunnel_addrs, 0) : NULL;
	const char *routing_dir_jni = routing_dir ? (*env)->GetStringUTFChars(env, routing_dir, 0) : NULL;
	const char *direct_dns_jni = direct_dns ? (*env)->GetStringUTFChars(env, direct_dns, 0) : NULL;

	// Duplicate strings to avoid MTE issues with JNI-tagged pointers during Go execution
	char *bind_ip_str = bind_ip_jni ? strdup(bind_ip_jni) : NULL;
	char *dns_str = dns_jni ? strdup(dns_jni) : NULL;
	char *tunnel_addrs_str = tunnel_addrs_jni ? strdup(tunnel_addrs_jni) : NULL;
	char *routing_dir_str = routing_dir_jni ? strdup(routing_dir_jni) : NULL;
	char *direct_dns_str = direct_dns_jni ? strdup(direct_dns_jni) : NULL;

	int ret = wgTetherStart(bind_ip_str, (int)port, dns_str, tunnel_addrs_str, routing_dir_str, direct_dns_str);

	(*env)->ReleaseStringUTFChars(env, bind_ip, bind_ip_jni);
	if (dns_jni)
		(*env)->ReleaseStringUTFChars(env, dns_servers, dns_jni);
	if (tunnel_addrs_jni)
		(*env)->ReleaseStringUTFChars(env, tunnel_addrs, tunnel_addrs_jni);
	if (routing_dir_jni)
		(*env)->ReleaseStringUTFChars(env, routing_dir, routing_dir_jni);
	if (direct_dns_jni)
		(*env)->ReleaseStringUTFChars(env, direct_dns, direct_dns_jni);
	free(bind_ip_str);
	free(dns_str);
	free(tunnel_addrs_str);
	free(routing_dir_str);
	free(direct_dns_str);

	return ret;
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTetherStop(JNIEnv *env, jclass c)
{
	wgTetherStop();
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTetherStats(JNIEnv *env, jclass c)
{
	jstring ret;
	char *stats = wgTetherStats();
	if (!stats)
		return NULL;
	ret = (*env)->NewStringUTF(env, stats);
	free(stats);
	return ret;
}

// Re-points protect_and_bind() at the physical network the proxy should dial
// over, the moment Android publishes it. The sole writer of that binding:
// wgTurnProxyStart/Stop deliberately leave it alone.
//
// Called from the raw, undebounced side of PhysicalNetworkMonitor, so the dialer
// learns about a handover in milliseconds while the restart keeps waiting for the
// path to settle. Before that, the binding only moved when the proxy restarted, so
// every dial in between — the whole connect grace window, and every retry of a
// start still working through the captcha ladder — bound to the network the
// session began on. By then a dead one: the bind threw, the exception was cleared
// below in protect_and_bind, and the socket went out protected-but-unbound.
//
// network == NULL means "no physical path": the socket is still protected, just
// deliberately left unbound, which leaves it on the system default route.
//
// dns_servers rides along because the resolver has to follow the network for the
// same reason the binding does — a handover leaves the dead network's resolvers
// at the head of the list otherwise. It is pushed outside the lock: Go must never
// be called with jni_globals_mutex held, and nothing here needs it.
JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgSetNetwork(JNIEnv *env, jclass c, jobject network, jlong handle, jstring dns_servers, jint relay_transport)
{
	pthread_mutex_lock(&jni_globals_mutex);
	set_current_network_locked(env, network, handle);
	pthread_mutex_unlock(&jni_globals_mutex);

	// Duplicated for the same reason wgTurnProxyStart duplicates its strings:
	// JNI-tagged pointers must not be handed to Go under MTE.
	const char *dns_jni = dns_servers ? (*env)->GetStringUTFChars(env, dns_servers, 0) : NULL;
	char *dns_str = dns_jni ? strdup(dns_jni) : NULL;
	if (dns_jni)
		(*env)->ReleaseStringUTFChars(env, dns_servers, dns_jni);
	wgSetSystemDns(dns_str ? dns_str : "");
	free(dns_str);

	// Last, so that workers woken by a returning path already resolve against its
	// DNS servers. With no path at all this parks every worker at the network
	// gate: until then the gate stayed open on transport proof earned over the
	// network that had just vanished, and the workers kept dialing nothing. The
	// handle, not just "is there one", because leaving a network also marks the
	// relays our allocations on it can no longer release.
	//
	// How this network's relays are reached (UDP, or TCP where UDP carries no
	// session) belongs to the network as much as its DNS servers do, and goes in
	// the same call as the handle: the dials a returning or a new network sets off
	// must already go out the right way, and a worker must not be able to start
	// an attempt on one half of the new state (see wgSetNetworkState).
	wgSetNetworkState(network != NULL ? (long long)handle : 0, (int)relay_transport);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnReadyStreams(JNIEnv *env, jclass c)
{
	return (jint)wgTurnReadyStreams();
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnDropCredentials(JNIEnv *env, jclass c)
{
	wgTurnDropCredentials();
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_TurnBackend_wgTurnProxyStop(JNIEnv *env, jclass c)
{
	// The cached Network outlives the proxy session on purpose: it describes the
	// device's connectivity, not this session, and wgSetNetwork() replaces it the
	// moment the monitor sees a different path. Dropping it here meant every stop
	// — including the ones the start path makes between stream-count attempts —
	// left the next dial unbound until something pushed the handle again, and
	// nothing does until the network changes.
	//
	// If a drop ever comes back here it must run AFTER wgTurnProxyStop():
	// releasing first left still-draining goroutines calling wgProtectSocket
	// against a deleted ref for the whole drain window.
	wgTurnProxyStop();
}


// Called from Go to request captcha solving from Android UI.
// visible picks the UI: 0 = invisible auto-clicking WebView, 1 = the full-screen
// dialog. Go owns the escalation ladder, so the mode is passed explicitly rather
// than inferred on the Java side.
// Blocks until the user solves the captcha or timeout.
// Returns a malloc'd string that the caller (Go) must free.
const char* requestCaptcha(const char* redirect_uri, int visible)
{
	JNIEnv *env;
	int attached = 0;
	const char* result = NULL;

	if (!java_vm) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI", "requestCaptcha: no JavaVM");
		return NULL;
	}

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"requestCaptcha: AttachCurrentThread failed");
			return NULL;
		}
		attached = 1;
	}

	// Snapshot and release the lock before calling in: the handler blocks for as
	// long as the user takes to solve the captcha (up to 120s).
	pthread_mutex_lock(&jni_globals_mutex);
	jclass tb_class = turn_backend_class_global ? (jclass)(*env)->NewLocalRef(env, turn_backend_class_global) : NULL;
	jmethodID on_captcha = on_captcha_required_method;
	pthread_mutex_unlock(&jni_globals_mutex);

	if (!tb_class || !on_captcha) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"requestCaptcha: JNI not initialized (class=%p, method=%p)", tb_class, on_captcha);
		if (tb_class) (*env)->DeleteLocalRef(env, tb_class);
		if (attached)
			(*java_vm)->DetachCurrentThread(java_vm);
		return NULL;
	}

	jstring j_uri = (*env)->NewStringUTF(env, redirect_uri);
	jstring j_result = (jstring)(*env)->CallStaticObjectMethod(env, tb_class, on_captcha, j_uri,
		visible ? JNI_TRUE : JNI_FALSE);
	(*env)->DeleteLocalRef(env, j_uri);
	(*env)->DeleteLocalRef(env, tb_class);

	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"requestCaptcha: exception occurred");
		(*env)->ExceptionClear(env);
	} else if (j_result != NULL) {
		// GetStringUTFChars returns NULL on allocation failure (and leaves an
		// OutOfMemoryError pending). Releasing a NULL pointer is undefined, so
		// the guard covers both the release and the strlen above it.
		const char* str = (*env)->GetStringUTFChars(env, j_result, NULL);
		if (str) {
			if (strlen(str) > 0)
				result = strdup(str);
			(*env)->ReleaseStringUTFChars(env, j_result, str);
		} else {
			(*env)->ExceptionClear(env);
		}
		(*env)->DeleteLocalRef(env, j_result);
	}

	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);

	__android_log_print(ANDROID_LOG_INFO, "WireGuard/JNI",
		"requestCaptcha: returning %s", result ? "token" : "NULL");
	return result;
}

// Called from Go when the proxy is stopping (or restarting) while a captcha may
// still be on screen. requestCaptcha blocks its worker goroutine inside the Java
// handler for as long as the user takes to solve the challenge — up to 120s —
// and neither the Go context nor wgTurnProxyStop could interrupt it, so a user
// who pressed disconnect kept a dialog alive and the next connect blocked behind
// the captcha mutex. This tells the Java side to abandon whatever it is showing;
// the pending requestCaptcha then returns an empty token almost immediately.
// Fire-and-forget: never blocks, swallows any Java-side exception.
void cancelCaptcha(void)
{
	JNIEnv *env;
	int attached = 0;

	if (!java_vm)
		return;

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"cancelCaptcha: AttachCurrentThread failed");
			return;
		}
		attached = 1;
	}

	pthread_mutex_lock(&jni_globals_mutex);
	jclass tb_class = turn_backend_class_global ? (jclass)(*env)->NewLocalRef(env, turn_backend_class_global) : NULL;
	jmethodID on_cancel = on_captcha_cancel_method;
	pthread_mutex_unlock(&jni_globals_mutex);

	if (!tb_class || !on_cancel) {
		if (tb_class) (*env)->DeleteLocalRef(env, tb_class);
		if (attached)
			(*java_vm)->DetachCurrentThread(java_vm);
		return;
	}

	(*env)->CallStaticVoidMethod(env, tb_class, on_cancel);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI", "cancelCaptcha: exception occurred");
		(*env)->ExceptionClear(env);
	}
	(*env)->DeleteLocalRef(env, tb_class);

	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
}

// Called from Go when VK has rejected the device identity the captcha layer is
// presenting (rate limit, BOT verdict, exhausted solve ladder). Tells the Java
// side to retire the current persona so the next captcha is attempted under a
// freshly minted one. Fire-and-forget: never blocks, swallows Java exceptions.
void burnCaptchaPersona(const char* reason)
{
	JNIEnv *env;
	int attached = 0;

	if (!java_vm)
		return;

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"burnCaptchaPersona: AttachCurrentThread failed");
			return;
		}
		attached = 1;
	}

	pthread_mutex_lock(&jni_globals_mutex);
	jclass tb_class = turn_backend_class_global ? (jclass)(*env)->NewLocalRef(env, turn_backend_class_global) : NULL;
	jmethodID on_burn = on_captcha_persona_burn_method;
	pthread_mutex_unlock(&jni_globals_mutex);

	if (!tb_class || !on_burn) {
		if (tb_class) (*env)->DeleteLocalRef(env, tb_class);
		if (attached)
			(*java_vm)->DetachCurrentThread(java_vm);
		return;
	}

	jstring j_reason = (*env)->NewStringUTF(env, reason ? reason : "");
	(*env)->CallStaticVoidMethod(env, tb_class, on_burn, j_reason);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI", "burnCaptchaPersona: exception occurred");
		(*env)->ExceptionClear(env);
	}
	(*env)->DeleteLocalRef(env, j_reason);
	(*env)->DeleteLocalRef(env, tb_class);

	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
}

// Called from Go when the TURN session has failed terminally — every worker gave
// up, so no retry will bring the tunnel back. Hands the reason to Java
// (TurnBackend.onTurnFatal) so the user is told and the tunnel is torn down
// instead of staying "connected" over a dead route. Fire-and-forget: never
// blocks the caller and swallows any Java-side exception.
void notifyTurnFatal(const char* reason)
{
	JNIEnv *env;
	int attached = 0;

	if (!java_vm)
		return;

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"notifyTurnFatal: AttachCurrentThread failed");
			return;
		}
		attached = 1;
	}

	pthread_mutex_lock(&jni_globals_mutex);
	jclass tb_class = turn_backend_class_global ? (jclass)(*env)->NewLocalRef(env, turn_backend_class_global) : NULL;
	jmethodID on_fatal = on_turn_fatal_method;
	pthread_mutex_unlock(&jni_globals_mutex);

	if (!tb_class || !on_fatal) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"notifyTurnFatal: JNI not initialized (class=%p, method=%p)", tb_class, on_fatal);
		if (tb_class) (*env)->DeleteLocalRef(env, tb_class);
		if (attached)
			(*java_vm)->DetachCurrentThread(java_vm);
		return;
	}

	jstring j_reason = (*env)->NewStringUTF(env, reason ? reason : "");
	(*env)->CallStaticVoidMethod(env, tb_class, on_fatal, j_reason);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI", "notifyTurnFatal: exception occurred");
		(*env)->ExceptionClear(env);
	}
	(*env)->DeleteLocalRef(env, j_reason);
	(*env)->DeleteLocalRef(env, tb_class);

	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
}

// Called from Go when the internet-sharing proxy retired itself — its accept
// loop hit an error no retry can fix, or the egress guard caught traffic that
// would have left outside the tunnel. Hands the reason to Java
// (TurnBackend.onTetherStopped) so the access point comes down with it.
//
// Without this the Kotlin side only notices at its next stats poll, which is
// thirty seconds apart while the screen is off: half a minute of a sheet
// advertising an SSID, a password and a QR for a proxy that will never serve
// another client. Fire-and-forget, exactly like notifyTurnFatal.
void notifyTetherStopped(const char* reason)
{
	JNIEnv *env;
	int attached = 0;

	if (!java_vm)
		return;

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"notifyTetherStopped: AttachCurrentThread failed");
			return;
		}
		attached = 1;
	}

	pthread_mutex_lock(&jni_globals_mutex);
	jclass tb_class = turn_backend_class_global ? (jclass)(*env)->NewLocalRef(env, turn_backend_class_global) : NULL;
	jmethodID on_stopped = on_tether_stopped_method;
	pthread_mutex_unlock(&jni_globals_mutex);

	if (!tb_class || !on_stopped) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"notifyTetherStopped: JNI not initialized (class=%p, method=%p)", tb_class, on_stopped);
		if (tb_class) (*env)->DeleteLocalRef(env, tb_class);
		if (attached)
			(*java_vm)->DetachCurrentThread(java_vm);
		return;
	}

	jstring j_reason = (*env)->NewStringUTF(env, reason ? reason : "");
	(*env)->CallStaticVoidMethod(env, tb_class, on_stopped, j_reason);
	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI", "notifyTetherStopped: exception occurred");
		(*env)->ExceptionClear(env);
	}
	(*env)->DeleteLocalRef(env, j_reason);
	(*env)->DeleteLocalRef(env, tb_class);

	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);
}

// Called from Go to fetch the captcha device profile (real screen/DPR/core/mem
// metrics + persisted browser_fp) as a JSON string. Returns a malloc'd string
// that the caller (Go) must free, or NULL if unavailable.
const char* getCaptchaDeviceProfile(void)
{
	JNIEnv *env;
	int attached = 0;
	const char* result = NULL;

	if (!java_vm) {
		return NULL;
	}

	if ((*java_vm)->GetEnv(java_vm, (void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED) {
		if ((*java_vm)->AttachCurrentThread(java_vm, &env, NULL) != 0) {
			__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
				"getCaptchaDeviceProfile: AttachCurrentThread failed");
			return NULL;
		}
		attached = 1;
	}

	pthread_mutex_lock(&jni_globals_mutex);
	jclass tb_class = turn_backend_class_global ? (jclass)(*env)->NewLocalRef(env, turn_backend_class_global) : NULL;
	jmethodID device_profile = get_captcha_device_profile_method;
	pthread_mutex_unlock(&jni_globals_mutex);

	if (!tb_class || !device_profile) {
		if (tb_class) (*env)->DeleteLocalRef(env, tb_class);
		if (attached)
			(*java_vm)->DetachCurrentThread(java_vm);
		return NULL;
	}

	jstring j_result = (jstring)(*env)->CallStaticObjectMethod(env, tb_class, device_profile);
	(*env)->DeleteLocalRef(env, tb_class);

	if ((*env)->ExceptionCheck(env)) {
		__android_log_print(ANDROID_LOG_ERROR, "WireGuard/JNI",
			"getCaptchaDeviceProfile: exception occurred");
		(*env)->ExceptionClear(env);
	} else if (j_result != NULL) {
		// See requestCaptcha: a NULL from GetStringUTFChars must not be released.
		const char* str = (*env)->GetStringUTFChars(env, j_result, NULL);
		if (str) {
			if (strlen(str) > 0)
				result = strdup(str);
			(*env)->ReleaseStringUTFChars(env, j_result, str);
		} else {
			(*env)->ExceptionClear(env);
		}
		(*env)->DeleteLocalRef(env, j_result);
	}

	if (attached)
		(*java_vm)->DetachCurrentThread(java_vm);

	return result;
}
