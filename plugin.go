package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var cpaSensitivePluginVersion = "0.1.0"

type sensitivePlugin struct {
	engine *engine
}

var _ pluginapi.RequestInterceptor = (*sensitivePlugin)(nil)
var _ pluginapi.ResponseInterceptor = (*sensitivePlugin)(nil)
var _ pluginapi.StreamChunkInterceptor = (*sensitivePlugin)(nil)
var _ pluginapi.ManagementAPI = (*sensitivePlugin)(nil)
var _ pluginapi.ManagementHandler = (*sensitivePlugin)(nil)

func buildPlugin(configYAML []byte) (pluginapi.Plugin, error) {
	cfg, err := parseConfig(configYAML)
	if err != nil {
		return pluginapi.Plugin{}, err
	}
	instance, err := newEngine(cfg)
	if err != nil {
		return pluginapi.Plugin{}, err
	}
	p := &sensitivePlugin{engine: instance}
	return pluginapi.Plugin{
		Metadata: pluginapi.Metadata{
			Name:             "CPA Sensitive",
			Version:          cpaSensitivePluginVersion,
			Author:           "Ironboxplus",
			GitHubRepository: "https://github.com/Ironboxplus/SensitivePromptMasker",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "sanitization", Type: pluginapi.ConfigFieldTypeObject, Description: "Octopus-compatible grouped literal replacements with explicit Claude/Codex/Chat adapters."},
				{Name: "privacy_shield", Type: pluginapi.ConfigFieldTypeObject, Description: "Gitleaks, PII and custom-regex request redaction with response restoration."},
				{Name: "session", Type: pluginapi.ConfigFieldTypeObject, Description: "Bounded request-to-response restoration state."},
			},
		},
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor:     p,
			ResponseInterceptor:    p,
			StreamChunkInterceptor: p,
			ManagementAPI:          p,
		},
	}, nil
}

func (p *sensitivePlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.engine.interceptBefore(ctx, req)
}

func (p *sensitivePlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.engine.interceptAfter(ctx, req)
}

func (p *sensitivePlugin) InterceptResponse(ctx context.Context, req pluginapi.ResponseInterceptRequest) (pluginapi.ResponseInterceptResponse, error) {
	return p.engine.interceptResponseContext(ctx, req), nil
}

func (p *sensitivePlugin) InterceptStreamChunk(ctx context.Context, req pluginapi.StreamChunkInterceptRequest) (pluginapi.StreamChunkInterceptResponse, error) {
	return p.engine.interceptStreamContext(ctx, req), nil
}

func (p *sensitivePlugin) RegisterManagement(context.Context, pluginapi.ManagementRegistrationRequest) (pluginapi.ManagementRegistrationResponse, error) {
	return pluginapi.ManagementRegistrationResponse{
		Resources: []pluginapi.ResourceRoute{{
			Path:        "/status",
			Menu:        "CPA Sensitive",
			Description: "Sanitization and Privacy Shield runtime status.",
			Handler:     p,
		}},
	}, nil
}

func (p *sensitivePlugin) HandleManagement(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	body, err := json.MarshalIndent(p.engine.status(), "", "  ")
	if err != nil {
		return pluginapi.ManagementResponse{}, err
	}
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       append(body, '\n'),
	}, nil
}
