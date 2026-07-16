package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	methodRegister         = pluginabi.MethodPluginRegister
	methodReconfigure      = pluginabi.MethodPluginReconfigure
	methodRequestBefore    = pluginabi.MethodRequestInterceptBefore
	methodRequestAfter     = pluginabi.MethodRequestInterceptAfter
	methodResponseAfter    = pluginabi.MethodResponseInterceptAfter
	methodResponseStream   = pluginabi.MethodResponseInterceptStreamChunk
	methodManagementReg    = pluginabi.MethodManagementRegister
	methodManagementHandle = pluginabi.MethodManagementHandle
)

var runtimeState = struct {
	sync.Mutex
	plugin       *sensitivePlugin
	shuttingDown bool
	inFlight     sync.WaitGroup
}{}

type envelope = pluginabi.Envelope
type envelopeError = pluginabi.Error

type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
	PluginDir  string `json:"plugin_dir,omitempty"`
}

type requestInterceptRPCRequest struct {
	pluginapi.RequestInterceptRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type responseInterceptRPCRequest struct {
	pluginapi.ResponseInterceptRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type streamChunkInterceptRPCRequest struct {
	pluginapi.StreamChunkInterceptRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type managementRPCRequest struct {
	pluginapi.ManagementRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type registration struct {
	SchemaVersion uint32                 `json:"schema_version"`
	Metadata      pluginapi.Metadata     `json:"metadata"`
	Capabilities  registrationCapability `json:"capabilities"`
}

type registrationCapability struct {
	RequestInterceptor     bool `json:"request_interceptor"`
	ResponseInterceptor    bool `json:"response_interceptor"`
	StreamChunkInterceptor bool `json:"response_stream_interceptor"`
	ManagementAPI          bool `json:"management_api"`
}

type managementRegistrationResponse struct {
	Resources []resourceRoute `json:"resources,omitempty"`
}

type resourceRoute struct {
	Path        string
	Menu        string
	Description string
}

func main() {}

func shutdownEngine() {
	runtimeState.Lock()
	runtimeState.shuttingDown = true
	runtimeState.plugin = nil
	runtimeState.Unlock()
	runtimeState.inFlight.Wait()
}

func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case methodRegister, methodReconfigure:
		return handleRegister(request)
	}

	p, done, err := beginPluginCall()
	if err != nil {
		return nil, err
	}
	defer done()

	switch method {
	case methodRequestBefore:
		var input requestInterceptRPCRequest
		if err := json.Unmarshal(request, &input); err != nil {
			return nil, err
		}
		output, err := p.InterceptRequestBeforeAuth(hostActivityContext(input.HostCallbackID), input.RequestInterceptRequest)
		return okEnvelopeWithError(output, err)
	case methodRequestAfter:
		var input requestInterceptRPCRequest
		if err := json.Unmarshal(request, &input); err != nil {
			return nil, err
		}
		output, err := p.InterceptRequestAfterAuth(hostActivityContext(input.HostCallbackID), input.RequestInterceptRequest)
		return okEnvelopeWithError(output, err)
	case methodResponseAfter:
		var input responseInterceptRPCRequest
		if err := json.Unmarshal(request, &input); err != nil {
			return nil, err
		}
		output, err := p.InterceptResponse(hostActivityContext(input.HostCallbackID), input.ResponseInterceptRequest)
		return okEnvelopeWithError(output, err)
	case methodResponseStream:
		var input streamChunkInterceptRPCRequest
		if err := json.Unmarshal(request, &input); err != nil {
			return nil, err
		}
		output, err := p.InterceptStreamChunk(hostActivityContext(input.HostCallbackID), input.StreamChunkInterceptRequest)
		return okEnvelopeWithError(output, err)
	case methodManagementReg:
		var input pluginapi.ManagementRegistrationRequest
		if len(request) != 0 {
			if err := json.Unmarshal(request, &input); err != nil {
				return nil, err
			}
		}
		output, err := p.RegisterManagement(context.Background(), input)
		if err != nil {
			return nil, err
		}
		resources := make([]resourceRoute, 0, len(output.Resources))
		for _, route := range output.Resources {
			resources = append(resources, resourceRoute{Path: route.Path, Menu: route.Menu, Description: route.Description})
		}
		return okEnvelope(managementRegistrationResponse{Resources: resources})
	case methodManagementHandle:
		var input managementRPCRequest
		if err := json.Unmarshal(request, &input); err != nil {
			return nil, err
		}
		output, err := p.HandleManagement(context.Background(), input.ManagementRequest)
		return okEnvelopeWithError(output, err)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func handleRegister(request []byte) ([]byte, error) {
	var lifecycle lifecycleRequest
	if err := json.Unmarshal(request, &lifecycle); err != nil {
		return nil, err
	}
	plugin, err := buildPlugin(lifecycle.ConfigYAML)
	if err != nil {
		return nil, err
	}
	p, ok := plugin.Capabilities.RequestInterceptor.(*sensitivePlugin)
	if !ok || p == nil {
		return nil, fmt.Errorf("cpa-sensitive registration returned invalid request interceptor")
	}
	runtimeState.Lock()
	runtimeState.plugin = p
	runtimeState.shuttingDown = false
	runtimeState.Unlock()
	return okEnvelope(pluginRegistration(plugin))
}

func beginPluginCall() (*sensitivePlugin, func(), error) {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if runtimeState.shuttingDown {
		return nil, nil, fmt.Errorf("cpa-sensitive plugin is shutting down")
	}
	if runtimeState.plugin == nil {
		return nil, nil, fmt.Errorf("plugin is not configured")
	}
	runtimeState.inFlight.Add(1)
	return runtimeState.plugin, runtimeState.inFlight.Done, nil
}

func activeEngine() *engine {
	runtimeState.Lock()
	defer runtimeState.Unlock()
	if runtimeState.plugin == nil {
		return nil
	}
	return runtimeState.plugin.engine
}

func pluginRegistration(plugin pluginapi.Plugin) registration {
	caps := plugin.Capabilities
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata:      plugin.Metadata,
		Capabilities: registrationCapability{
			RequestInterceptor:     caps.RequestInterceptor != nil,
			ResponseInterceptor:    caps.ResponseInterceptor != nil,
			StreamChunkInterceptor: caps.StreamChunkInterceptor != nil,
			ManagementAPI:          caps.ManagementAPI != nil,
		},
	}
}

func okEnvelopeWithError(value any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return okEnvelope(value)
}

func okEnvelope(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}
