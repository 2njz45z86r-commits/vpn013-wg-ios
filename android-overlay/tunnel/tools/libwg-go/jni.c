/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include "r013_android_bridge.h"

struct go_string { const char *str; long n; };
extern int awgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings);
extern void awgTurnOff(int handle);
extern int awgGetSocketV4(int handle);
extern int awgGetSocketV6(int handle);
extern char *awgGetConfig(int handle);
extern char *awgVersion();

JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_awgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
	const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
	size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
	const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
	size_t settings_len = (*env)->GetStringUTFLength(env, settings);
	int ret = awgTurnOn((struct go_string){
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

JNIEXPORT void JNICALL Java_org_amnezia_awg_GoBackend_awgTurnOff(JNIEnv *env, jclass c, jint handle)
{
	awgTurnOff(handle);
}

JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_awgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
	return awgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_awgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
	return awgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_org_amnezia_awg_GoBackend_awgGetConfig(JNIEnv *env, jclass c, jint handle)
{
	jstring ret;
	char *config = awgGetConfig(handle);
	if (!config)
		return NULL;
	ret = (*env)->NewStringUTF(env, config);
	free(config);
	return ret;
}

JNIEXPORT jstring JNICALL Java_org_amnezia_awg_GoBackend_awgVersion(JNIEnv *env, jclass c)
{
	jstring ret;
	char *version = awgVersion();
	if (!version)
		return NULL;
	ret = (*env)->NewStringUTF(env, version);
	free(version);
	return ret;
}

/* A fixed two-slot pool holds immutable platform routes during provider
 * handover. Packets never cross JNI; only a fresh unconnected FD is gated. */
static JavaVM *r013_vm;
static pthread_mutex_t r013_gates_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t r013_next_gate;
struct r013_gate { uint64_t id; jobject object; jmethodID prepare; };
static struct r013_gate r013_gates[2];

extern int r013ProxyStart(long long, const char *, int, long long);
extern int r013ProxyStop(long long);
extern char *r013ProxyStats(void);
extern long long r013ProxyProbe(const char *, long long);
JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_r013ProxyStart(JNIEnv *env, jclass c, jlong ticket, jstring input, jint fd, jobject gate);
JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_r013ProxyStop(JNIEnv *env, jclass c, jlong ticket)
{ (void)env; (void)c; return r013ProxyStop(ticket); }
JNIEXPORT jstring JNICALL Java_org_amnezia_awg_GoBackend_r013ProxyStats(JNIEnv *env, jclass c)
{
    (void)c; char *wire = r013ProxyStats(); if (!wire) return NULL;
    jstring result = (*env)->NewStringUTF(env, wire); free(wire); return result;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	(void)reserved;
	r013_vm = vm;
	return JNI_VERSION_1_6;
}

static JNIEnv *r013_env(int *attached)
{
	JNIEnv *env = NULL;
	*attached = 0;
	if (!r013_vm) return NULL;
	jint result = (*r013_vm)->GetEnv(r013_vm, (void **)&env, JNI_VERSION_1_6);
	if (result == JNI_EDETACHED) {
		if ((*r013_vm)->AttachCurrentThread(r013_vm, &env, NULL) != JNI_OK) return NULL;
		*attached = 1;
	} else if (result != JNI_OK) return NULL;
	return env;
}

static uint64_t r013_register_gate(JNIEnv *env, jobject object)
{
	if (!object) return 0;
	jclass type = (*env)->GetObjectClass(env, object);
	if (!type) return 0;
	jmethodID prepare = (*env)->GetMethodID(env, type, "prepareSocket", "(II)Z");
	(*env)->DeleteLocalRef(env, type);
	if (!prepare) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return 0; }
	pthread_mutex_lock(&r013_gates_lock);
	uint64_t id = 0;
	for (size_t i = 0; i < 2; ++i) {
		if (r013_gates[i].id) continue;
		jobject global = (*env)->NewGlobalRef(env, object);
		if (!global) break;
		id = ++r013_next_gate;
		r013_gates[i] = (struct r013_gate){id, global, prepare};
		break;
	}
	pthread_mutex_unlock(&r013_gates_lock);
	return id;
}

JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_r013ProxyStart(JNIEnv *env, jclass c, jlong ticket, jstring input, jint fd, jobject gate)
{
    (void)c;
    if (!input || fd < 0) return -1;
    jsize size = (*env)->GetStringUTFLength(env, input);
    if (size <= 0 || size > 1048576) return -1;
    uint64_t registered = r013_register_gate(env, gate); if (!registered) return -1;
    const char *wire = (*env)->GetStringUTFChars(env, input, 0);
    if (!wire) { r013_gate_release(registered); return -1; }
    int result = r013ProxyStart(ticket, wire, fd, (long long)registered);
    (*env)->ReleaseStringUTFChars(env, input, wire);
    if (result != 0) r013_gate_release(registered);
    return result;
}

JNIEXPORT jlong JNICALL Java_org_amnezia_awg_GoBackend_r013ProxyProbe(JNIEnv *env, jclass c, jstring input, jobject gate)
{
    (void)c; if (!input) return -1;
    jsize size = (*env)->GetStringUTFLength(env, input); if (size <= 0 || size > 1048576) return -1;
    uint64_t registered = r013_register_gate(env, gate); if (!registered) return -1;
    const char *wire = (*env)->GetStringUTFChars(env, input, 0);
    if (!wire) { r013_gate_release(registered); return -1; }
    long long result = r013ProxyProbe(wire, registered);
    (*env)->ReleaseStringUTFChars(env, input, wire); r013_gate_release(registered); return result;
}

int r013_gate_prepare(uint64_t id, int route, int fd)
{
	if (fd < 0 || (route != 1 && route != 2)) return 0;
	int attached;
	JNIEnv *env = r013_env(&attached);
	if (!env) return 0;
	jobject local = NULL;
	jmethodID prepare = NULL;
	pthread_mutex_lock(&r013_gates_lock);
	for (size_t i = 0; i < 2; ++i) {
		if (r013_gates[i].id != id) continue;
		local = (*env)->NewLocalRef(env, r013_gates[i].object);
		prepare = r013_gates[i].prepare;
		break;
	}
	pthread_mutex_unlock(&r013_gates_lock);
	jboolean result = JNI_FALSE;
	if (local && prepare) result = (*env)->CallBooleanMethod(env, local, prepare, (jint)route, (jint)fd);
	if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); result = JNI_FALSE; }
	if (local) (*env)->DeleteLocalRef(env, local);
	if (attached) (*r013_vm)->DetachCurrentThread(r013_vm);
	return result == JNI_TRUE ? 1 : 0;
}

void r013_gate_release(uint64_t id)
{
	int attached;
	JNIEnv *env = r013_env(&attached);
	if (!env) return;
	pthread_mutex_lock(&r013_gates_lock);
	for (size_t i = 0; i < 2; ++i) {
		if (r013_gates[i].id != id) continue;
		(*env)->DeleteGlobalRef(env, r013_gates[i].object);
		r013_gates[i] = (struct r013_gate){0};
		break;
	}
	pthread_mutex_unlock(&r013_gates_lock);
	if (attached) (*r013_vm)->DetachCurrentThread(r013_vm);
}

extern long long r013PrimaryBegin(void);
extern int r013PrimaryEnd(long long);
extern int awgTurnOnGuarded(long long, struct go_string, int, struct go_string);
extern int awgTurnOffGuarded(long long, int);
extern char *awgGetInterfaceName(int);
extern long long r013ProbeCreate(long long);
extern void r013ProbeInvalidate(long long);
extern int r013ProbeRefresh(long long);
extern long long r013ProbeStart(long long, const char *, int);
extern char *r013ProbePoll(long long, long long);
extern long long r013ProbeChoose(long long, long long, const char *, int);
extern int r013ProbeRelease(long long);

JNIEXPORT jlong JNICALL Java_org_amnezia_awg_GoBackend_r013PrimaryBegin(JNIEnv *env, jclass c)
{ (void)env; (void)c; return r013PrimaryBegin(); }
JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_r013PrimaryEnd(JNIEnv *env, jclass c, jlong ticket)
{ (void)env; (void)c; return r013PrimaryEnd(ticket); }
JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_awgTurnOffGuarded(JNIEnv *env, jclass c, jlong ticket, jint handle)
{ (void)env; (void)c; return awgTurnOffGuarded(ticket, handle); }
JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_awgTurnOnGuarded(JNIEnv *env, jclass c, jlong ticket, jstring ifname, jint fd, jstring settings)
{
	(void)c;
	if (!ifname || !settings) { close(fd); return -1; }
	const char *name = (*env)->GetStringUTFChars(env, ifname, 0);
	if (!name) { close(fd); return -1; }
	const char *config = (*env)->GetStringUTFChars(env, settings, 0);
	if (!config) { (*env)->ReleaseStringUTFChars(env, ifname, name); close(fd); return -1; }
	int result = awgTurnOnGuarded(ticket,
		(struct go_string){name, (*env)->GetStringUTFLength(env, ifname)}, fd,
		(struct go_string){config, (*env)->GetStringUTFLength(env, settings)});
	(*env)->ReleaseStringUTFChars(env, settings, config);
	(*env)->ReleaseStringUTFChars(env, ifname, name);
	return result;
}
JNIEXPORT jstring JNICALL Java_org_amnezia_awg_GoBackend_awgGetInterfaceName(JNIEnv *env, jclass c, jint handle)
{
	(void)c; char *name = awgGetInterfaceName(handle); if (!name) return NULL;
	jstring value = (*env)->NewStringUTF(env, name); free(name); return value;
}
JNIEXPORT jlong JNICALL Java_org_amnezia_awg_GoBackend_r013ProbeCreate(JNIEnv *env, jclass c, jobject gate)
{
	(void)c; uint64_t registered = r013_register_gate(env, gate); if (!registered) return 0;
	long long handle = r013ProbeCreate((long long)registered);
	if (!handle) r013_gate_release(registered);
	return handle;
}
JNIEXPORT void JNICALL Java_org_amnezia_awg_GoBackend_r013ProbeInvalidate(JNIEnv *env, jclass c, jlong scope)
{ (void)env; (void)c; r013ProbeInvalidate(scope); }
JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_r013ProbeRefresh(JNIEnv *env, jclass c, jlong scope)
{ (void)env; (void)c; return r013ProbeRefresh(scope); }
JNIEXPORT jint JNICALL Java_org_amnezia_awg_GoBackend_r013ProbeRelease(JNIEnv *env, jclass c, jlong scope)
{ (void)env; (void)c; return r013ProbeRelease(scope); }
JNIEXPORT jlong JNICALL Java_org_amnezia_awg_GoBackend_r013ProbeStart(JNIEnv *env, jclass c, jlong scope, jstring input)
{
	(void)c; if (!input) return 0; jsize length = (*env)->GetStringUTFLength(env, input);
	if (length <= 0 || length > 4*1024*1024) return 0;
	const char *wire = (*env)->GetStringUTFChars(env, input, 0); if (!wire) return 0;
	long long result = r013ProbeStart(scope, wire, length);
	(*env)->ReleaseStringUTFChars(env, input, wire); return result;
}
JNIEXPORT jlong JNICALL Java_org_amnezia_awg_GoBackend_r013ProbeChoose(JNIEnv *env, jclass c, jlong scope, jlong operation, jstring input)
{
	(void)c; if (!input) return 0; jsize length = (*env)->GetStringUTFLength(env, input);
	if (length <= 0 || length > 4*1024*1024) return 0;
	const char *wire = (*env)->GetStringUTFChars(env, input, 0); if (!wire) return 0;
	long long result = r013ProbeChoose(scope, operation, wire, length);
	(*env)->ReleaseStringUTFChars(env, input, wire); return result;
}
JNIEXPORT jstring JNICALL Java_org_amnezia_awg_GoBackend_r013ProbePoll(JNIEnv *env, jclass c, jlong scope, jlong operation)
{
	(void)c; char *wire = r013ProbePoll(scope, operation); if (!wire) return NULL;
	jstring value = (*env)->NewStringUTF(env, wire); free(wire); return value;
}
