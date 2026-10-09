package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	pluginIdentifier = "apikeys"
	displayName      = "API Key Manager" // plugin name and PLUGINS menu label in the panel
	repositoryURL    = "https://github.com/ducdao98z/cpa-plugin-apikeys"
	defaultDataFile  = "plugins/apikeys.json"
)

// pluginVersion is set from the release tag with -ldflags "-X main.pluginVersion=...".
var pluginVersion = "0.3.0"

var store = &keyStore{keys: map[string]*keyEntry{}}

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type pluginConfig struct {
	DataFile string `yaml:"data-file"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	RequestInterceptor bool `json:"request_interceptor"`
	UsagePlugin        bool `json:"usage_plugin"`
	ManagementAPI      bool `json:"management_api"`
}

// interceptRequest keeps only what the limit check needs; the request body is skipped, not decoded.
type interceptRequest struct {
	Model          string
	RequestedModel string
	Metadata       struct {
		CallerScope string `json:"caller_scope"` // sha256 of the client API key, see callerScope
	}
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(host)
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
		writeResponse(response, errorEnvelope(pluginabi.NewError("invalid_method", "method is required")))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleMethod(C.GoString(method), requestBytes)
	if errHandle != nil {
		writeResponse(response, errorEnvelope(pluginabi.NewError("plugin_error", errHandle.Error())))
		return 1
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
func cliproxyPluginShutdown() { flushStore() }

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if errConfigure := configure(request); errConfigure != nil {
			return nil, errConfigure
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		flushStore()
		return okEnvelope(struct{}{})
	case pluginabi.MethodRequestInterceptBefore:
		var req interceptRequest
		if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
			return nil, errUnmarshal
		}
		status, body := store.rejection(req.Metadata.CallerScope, req.RequestedModel, req.Model, time.Now())
		if status == 0 {
			return okEnvelope(struct{}{})
		}
		return okEnvelope(pluginapi.RequestInterceptResponse{
			Terminate:       true,
			StatusCode:      status,
			ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
			ResponseBody:    body,
		})
	case pluginabi.MethodRequestInterceptAfter:
		return okEnvelope(struct{}{})
	case pluginabi.MethodUsageHandle:
		var rec pluginapi.UsageRecord
		if errUnmarshal := json.Unmarshal(request, &rec); errUnmarshal != nil {
			return nil, errUnmarshal
		}
		store.record(rec, time.Now())
		return okEnvelope(struct{}{})
	case pluginabi.MethodManagementRegister:
		return okEnvelope(managementRegistration())
	case pluginabi.MethodManagementHandle:
		var req pluginapi.ManagementRequest
		if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
			return nil, errUnmarshal
		}
		return okEnvelope(handleManagement(req, time.Now()))
	default:
		return errorEnvelope(pluginabi.NewError("unknown_method", "unknown method: "+method)), nil
	}
}

func configure(raw []byte) error {
	var req lifecycleRequest
	if len(raw) > 0 {
		if errUnmarshal := json.Unmarshal(raw, &req); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	var cfg pluginConfig
	if len(req.ConfigYAML) > 0 {
		if errUnmarshal := yaml.Unmarshal(req.ConfigYAML, &cfg); errUnmarshal != nil {
			return errUnmarshal
		}
	}
	path := strings.TrimSpace(cfg.DataFile)
	if path == "" {
		path = defaultDataFile
	}
	if errOpen := store.open(path); errOpen != nil {
		// Limits still apply to keys saved from now on, but nothing is written until the file is fixed.
		hostLog("error", "apikeys: "+errOpen.Error())
	}
	return nil
}

func flushStore() {
	if errFlush := store.flush(); errFlush != nil {
		hostLog("warn", "apikeys: "+errFlush.Error())
	}
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             displayName,
			Version:          pluginVersion,
			Author:           "ducdao98z",
			GitHubRepository: repositoryURL,
			ConfigFields: []pluginapi.ConfigField{
				{Name: "data-file", Type: pluginapi.ConfigFieldTypeString, Description: "Key limits and usage file (JSON). Default: " + defaultDataFile + " (relative to the CLIProxyAPI working directory)."},
			},
		},
		Capabilities: registrationCapability{
			RequestInterceptor: true,
			UsagePlugin:        true,
			ManagementAPI:      true,
		},
	}
}

func hostLog(level, message string) {
	_, _ = callHost(pluginabi.MethodHostLog, map[string]string{"level": level, "message": message})
}

func callHost(method string, payload any) (json.RawMessage, error) {
	rawPayload, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("marshal host callback %s: %w", method, errMarshal)
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	cPayload := C.CBytes(rawPayload)
	defer C.free(cPayload)
	var response C.cliproxy_buffer
	callCode := C.call_host_api(cMethod, (*C.uint8_t)(cPayload), C.size_t(len(rawPayload)), &response)
	var rawResponse []byte
	if response.ptr != nil {
		rawResponse = C.GoBytes(response.ptr, C.int(response.len))
		C.free_host_buffer(response.ptr, response.len)
	}
	var env pluginabi.Envelope
	if errUnmarshal := json.Unmarshal(rawResponse, &env); errUnmarshal != nil {
		return nil, fmt.Errorf("host callback %s failed, code=%d", method, int(callCode))
	}
	if !env.OK {
		if env.Error != nil {
			return nil, env.Error
		}
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	return env.Result, nil
}

func okEnvelope(v any) ([]byte, error) {
	raw, errMarshal := json.Marshal(v)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
}

func errorEnvelope(e *pluginabi.Error) []byte {
	raw, _ := json.Marshal(pluginabi.Envelope{OK: false, Error: e})
	return raw
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
