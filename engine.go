package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const cpaRequestIDMetadataKey = "cpa_request_id"

// Keep the historical internal names as aliases so the protocol-neutral core
// and its tests remain stable while the CPA boundary is compiler-checked
// against the official SDK.
type requestInterceptRequest = pluginapi.RequestInterceptRequest
type requestInterceptResponse = pluginapi.RequestInterceptResponse
type responseInterceptRequest = pluginapi.ResponseInterceptRequest
type responseInterceptResponse = pluginapi.ResponseInterceptResponse
type streamChunkInterceptRequest = pluginapi.StreamChunkInterceptRequest
type streamChunkInterceptResponse = pluginapi.StreamChunkInterceptResponse

type sessionEntry struct {
	session   *privacySession
	expiresAt time.Time
}

type engine struct {
	cfg      config
	detector detector

	mu       sync.Mutex
	sessions map[string]sessionEntry
	streams  map[string]*streamRestorer

	sanitizedReplacements atomic.Uint64
	redactedMappings      atomic.Uint64
	restoredMarkers       atomic.Uint64
}

func newEngine(cfg config) (*engine, error) {
	privacyDetector, err := newDetector(cfg.Privacy)
	if err != nil {
		return nil, err
	}
	return &engine{
		cfg: cfg, detector: privacyDetector,
		sessions: make(map[string]sessionEntry), streams: make(map[string]*streamRestorer),
	}, nil
}

func (e *engine) interceptBefore(ctx context.Context, request requestInterceptRequest) (requestInterceptResponse, error) {
	body, count, err := sanitizeRequest(request.Body, e.cfg.Sanitization, request.Model, request.SourceFormat, request.ToFormat)
	if err != nil {
		return requestInterceptResponse{}, err
	}
	e.sanitizedReplacements.Add(uint64(count))
	emitActivity(ctx, activityEvent{
		Stage: "request.sanitized", Model: request.Model, SourceFormat: request.SourceFormat,
		ToFormat: request.ToFormat, RequestID: requestKey(request.Metadata, request.Body, request.Model), Count: count,
	})
	return requestInterceptResponse{Body: body}, nil
}

func (e *engine) interceptAfter(ctx context.Context, request requestInterceptRequest) (requestInterceptResponse, error) {
	sanitized, count, err := sanitizeRequestAfterAuth(request.Body, e.cfg.Sanitization, request.Model, request.SourceFormat, request.ToFormat)
	if err != nil {
		return requestInterceptResponse{}, err
	}
	e.sanitizedReplacements.Add(uint64(count))
	emitActivity(ctx, activityEvent{
		Stage: "request.sanitized", Model: request.Model, SourceFormat: request.SourceFormat,
		ToFormat: request.ToFormat, RequestID: requestKey(request.Metadata, request.Body, request.Model), Count: count,
	})
	session, body, err := redactJSON(ctx, sanitized, e.cfg.Privacy, e.detector)
	if err != nil {
		return requestInterceptResponse{}, err
	}
	if len(session.Mappings) != 0 {
		key := requestKey(request.Metadata, sanitized, request.Model)
		e.storeSession(key, session)
		redactedKey := requestKey(request.Metadata, body, request.Model)
		if redactedKey != key {
			e.storeSession(redactedKey, session)
		}
		e.redactedMappings.Add(uint64(len(session.Mappings)))
		emitActivity(ctx, activityEvent{
			Stage: "request.redacted", Model: request.Model, SourceFormat: request.SourceFormat,
			ToFormat: request.ToFormat, RequestID: requestKey(request.Metadata, sanitized, request.Model), Count: len(session.Mappings),
		})
	}
	return requestInterceptResponse{Body: body}, nil
}

func (e *engine) interceptResponse(request responseInterceptRequest) responseInterceptResponse {
	return e.interceptResponseContext(context.Background(), request)
}

func (e *engine) interceptResponseContext(ctx context.Context, request responseInterceptRequest) responseInterceptResponse {
	key := requestKey(request.Metadata, request.RequestBody, request.Model)
	session := e.takeSession(key, true)
	body, count := restoreJSONBytes(request.Body, session)
	e.restoredMarkers.Add(uint64(count))
	emitActivity(ctx, activityEvent{
		Stage: "response.restored", Model: request.Model, SourceFormat: request.SourceFormat,
		RequestID: key, Count: count,
	})
	return responseInterceptResponse{Body: body}
}

func (e *engine) interceptStream(request streamChunkInterceptRequest) streamChunkInterceptResponse {
	return e.interceptStreamContext(context.Background(), request)
}

func (e *engine) interceptStreamContext(ctx context.Context, request streamChunkInterceptRequest) streamChunkInterceptResponse {
	key := requestKey(request.Metadata, request.RequestBody, request.Model)
	if request.ChunkIndex < 0 {
		e.ensureStream(key, request.SourceFormat)
		return streamChunkInterceptResponse{}
	}
	restorer := e.ensureStream(key, request.SourceFormat)
	if restorer == nil {
		return streamChunkInterceptResponse{Body: request.Body}
	}
	body, drop, count := restorer.feed(request.Body)
	e.restoredMarkers.Add(uint64(count))
	emitActivity(ctx, activityEvent{
		Stage: "response.restored", Model: request.Model, SourceFormat: request.SourceFormat,
		RequestID: key, Count: count, Stream: true,
	})
	if restorer != nil && restorer.streamTerminal(request.Body) {
		e.mu.Lock()
		delete(e.streams, key)
		delete(e.sessions, key)
		e.mu.Unlock()
	}
	return streamChunkInterceptResponse{Body: body, DropChunk: drop}
}

func (e *engine) storeSession(key string, session *privacySession) {
	if key == "" || session == nil {
		return
	}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneLocked(now)
	if len(e.sessions) >= e.cfg.Session.MaxSessions {
		var oldestKey string
		var oldest time.Time
		for candidate, entry := range e.sessions {
			if oldestKey == "" || entry.expiresAt.Before(oldest) {
				oldestKey, oldest = candidate, entry.expiresAt
			}
		}
		delete(e.sessions, oldestKey)
		delete(e.streams, oldestKey)
	}
	e.sessions[key] = sessionEntry{session: session, expiresAt: now.Add(time.Duration(e.cfg.Session.TTLSeconds) * time.Second)}
}

func (e *engine) takeSession(key string, remove bool) *privacySession {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneLocked(time.Now())
	entry, ok := e.sessions[key]
	if !ok {
		return nil
	}
	if remove {
		delete(e.sessions, key)
		delete(e.streams, key)
	}
	return entry.session
}

func (e *engine) ensureStream(key, format string) *streamRestorer {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneLocked(time.Now())
	if stream := e.streams[key]; stream != nil {
		return stream
	}
	entry, ok := e.sessions[key]
	if !ok {
		return nil
	}
	stream := &streamRestorer{session: entry.session, adapter: adapterForFormat(format)}
	e.streams[key] = stream
	return stream
}

func (e *engine) pruneLocked(now time.Time) {
	for key, entry := range e.sessions {
		if !entry.expiresAt.After(now) {
			delete(e.sessions, key)
			delete(e.streams, key)
		}
	}
}

func requestKey(metadata map[string]any, requestBody []byte, model string) string {
	if metadata != nil {
		if value, ok := metadata[cpaRequestIDMetadataKey].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	hash := sha256.New()
	_, _ = hash.Write(requestBody)
	_, _ = hash.Write([]byte("\x00" + model))
	return "fallback-" + hex.EncodeToString(hash.Sum(nil)[:16])
}

type engineStatus struct {
	Enabled               bool     `json:"enabled"`
	SanitizationEnabled   bool     `json:"sanitization_enabled"`
	PrivacyShieldEnabled  bool     `json:"privacy_shield_enabled"`
	ActiveSessions        int      `json:"active_sessions"`
	ActiveStreams         int      `json:"active_streams"`
	SanitizedReplacements uint64   `json:"sanitized_replacements"`
	RedactedMappings      uint64   `json:"redacted_mappings"`
	RestoredMarkers       uint64   `json:"restored_markers"`
	Warnings              []string `json:"warnings,omitempty"`
}

func (e *engine) status() engineStatus {
	e.mu.Lock()
	e.pruneLocked(time.Now())
	sessions, streams := len(e.sessions), len(e.streams)
	e.mu.Unlock()
	return engineStatus{
		Enabled: e.cfg.Enabled, SanitizationEnabled: e.cfg.Sanitization.Enabled,
		PrivacyShieldEnabled: e.cfg.Privacy.Enabled, ActiveSessions: sessions, ActiveStreams: streams,
		SanitizedReplacements: e.sanitizedReplacements.Load(), RedactedMappings: e.redactedMappings.Load(),
		RestoredMarkers: e.restoredMarkers.Load(), Warnings: e.cfg.migrationWarnings(),
	}
}
