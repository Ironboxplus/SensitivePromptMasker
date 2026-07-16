package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct { uint32_t abi_version; void* host_ctx; cliproxy_host_call_fn call; cliproxy_host_free_fn free_buffer; } cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct { uint32_t abi_version; cliproxy_plugin_call_fn call; cliproxy_plugin_free_fn free_buffer; cliproxy_plugin_shutdown_fn shutdown; } cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static int cpa_sensitive_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}

static void cpa_sensitive_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

const maxCGoBytesLen = C.size_t(1<<31 - 1)

var cpaSensitiveABIHostState = struct {
	sync.RWMutex
	host *C.cliproxy_host_api
}{}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil {
		return 1
	}
	cpaSensitiveABIHostState.Lock()
	cpaSensitiveABIHostState.host = host
	cpaSensitiveABIHostState.Unlock()
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 0
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		if requestLen > maxCGoBytesLen {
			writeResponse(response, errorEnvelope("request_too_large", "request payload is too large"))
			return 0
		}
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, err := handleMethod(C.GoString(method), requestBytes)
	if err != nil {
		writeResponse(response, errorEnvelope("plugin_error", err.Error()))
		return 0
	}
	writeResponse(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	shutdownEngine()
	cpaSensitiveABIHostState.Lock()
	cpaSensitiveABIHostState.host = nil
	cpaSensitiveABIHostState.Unlock()
}

func sendCPASensitiveHostLog(payload []byte) ([]byte, error) {
	return callCPASensitiveHost(pluginabi.MethodHostLog, payload)
}

func callCPASensitiveHost(method string, payload []byte) ([]byte, error) {
	cpaSensitiveABIHostState.RLock()
	defer cpaSensitiveABIHostState.RUnlock()
	if cpaSensitiveABIHostState.host == nil {
		return nil, fmt.Errorf("host callback is unavailable")
	}

	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var cPayload unsafe.Pointer
	if len(payload) != 0 {
		cPayload = C.CBytes(payload)
		if cPayload == nil {
			return nil, fmt.Errorf("allocate host callback payload")
		}
		defer C.free(cPayload)
	}

	var response C.cliproxy_buffer
	rc := C.cpa_sensitive_call_host(
		cpaSensitiveABIHostState.host,
		cMethod,
		(*C.uint8_t)(cPayload),
		C.size_t(len(payload)),
		&response,
	)
	var out []byte
	if response.ptr != nil && response.len != 0 {
		if response.len > maxCGoBytesLen {
			C.cpa_sensitive_free_host_buffer(cpaSensitiveABIHostState.host, response.ptr, response.len)
			return nil, fmt.Errorf("host callback response is too large")
		}
		out = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.cpa_sensitive_free_host_buffer(cpaSensitiveABIHostState.host, response.ptr, response.len)
	}
	if rc != 0 {
		return nil, fmt.Errorf("host callback %s returned %d: %s", method, int(rc), string(out))
	}
	return out, nil
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
