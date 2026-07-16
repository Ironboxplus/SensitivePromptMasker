package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
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
	return requestInterceptResponse{Headers: maskForwardedHost(request.Headers), Body: body}, nil
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
	redactStarted := time.Now()
	session, body, err := redactJSON(ctx, sanitized, e.cfg.Privacy, e.detector)
	redactElapsed := time.Since(redactStarted)
	if err != nil {
		return requestInterceptResponse{}, err
	}
	if len(session.Mappings) != 0 {
		e.storeSession(session, sessionLookupKeys(
			request.Metadata,
			[][]byte{sanitized, body},
			request.Model,
			request.RequestedModel,
		)...)
		e.redactedMappings.Add(uint64(len(session.Mappings)))
		emitActivity(ctx, activityEvent{
			Stage: "request.redacted", Model: request.Model, SourceFormat: request.SourceFormat,
			ToFormat: request.ToFormat, RequestID: requestKey(request.Metadata, sanitized, request.Model), Count: len(session.Mappings),
			RuleCounts: session.ruleCountsSnapshot(), Elapsed: redactElapsed,
		})
	}
	return requestInterceptResponse{Headers: maskForwardedHost(request.Headers), Body: body}, nil
}

func maskForwardedHost(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	masked := headers.Clone()
	found := false
	for key := range masked {
		if strings.EqualFold(key, "X-Forwarded-Host") {
			delete(masked, key)
			found = true
		}
	}
	if found {
		masked.Set("X-Forwarded-Host", "api.anthropic.com")
	}
	return masked
}

func (e *engine) interceptResponse(request responseInterceptRequest) responseInterceptResponse {
	return e.interceptResponseContext(context.Background(), request)
}

func (e *engine) interceptResponseContext(ctx context.Context, request responseInterceptRequest) responseInterceptResponse {
	keys := sessionLookupKeys(
		request.Metadata,
		[][]byte{request.RequestBody, request.OriginalRequest},
		request.Model,
		request.RequestedModel,
	)
	key := firstSessionKey(keys, request.Metadata, request.RequestBody, request.Model)
	session := e.takeSession(keys, true, request.RequestBody, request.OriginalRequest, request.Body)
	restoreStarted := time.Now()
	body, count := restoreJSONBytes(request.Body, session)
	restoreElapsed := time.Since(restoreStarted)
	e.restoredMarkers.Add(uint64(count))
	emitActivity(ctx, activityEvent{
		Stage: "response.restored", Model: request.Model, SourceFormat: request.SourceFormat,
		RequestID: key, Count: count, Elapsed: restoreElapsed,
	})
	return responseInterceptResponse{Body: body}
}

func (e *engine) interceptStream(request streamChunkInterceptRequest) streamChunkInterceptResponse {
	return e.interceptStreamContext(context.Background(), request)
}

func (e *engine) interceptStreamContext(ctx context.Context, request streamChunkInterceptRequest) streamChunkInterceptResponse {
	keys := sessionLookupKeys(
		request.Metadata,
		[][]byte{request.RequestBody, request.OriginalRequest},
		request.Model,
		request.RequestedModel,
	)
	key := firstSessionKey(keys, request.Metadata, request.RequestBody, request.Model)
	if request.ChunkIndex < 0 {
		e.ensureStream(keys, request.SourceFormat, request.RequestBody, request.OriginalRequest)
		return streamChunkInterceptResponse{}
	}
	restorer := e.ensureStream(keys, request.SourceFormat, request.RequestBody, request.OriginalRequest, request.Body)
	if restorer == nil {
		return streamChunkInterceptResponse{Body: request.Body}
	}
	restoreStarted := time.Now()
	body, drop, count := restorer.feed(request.Body)
	restoreElapsed := time.Since(restoreStarted)
	e.restoredMarkers.Add(uint64(count))
	emitActivity(ctx, activityEvent{
		Stage: "response.restored", Model: request.Model, SourceFormat: request.SourceFormat,
		RequestID: key, Count: count, Stream: true, Elapsed: restoreElapsed,
	})
	if restorer != nil && restorer.streamTerminal(request.Body) {
		e.mu.Lock()
		e.deleteSessionLocked(restorer.session)
		e.mu.Unlock()
	}
	return streamChunkInterceptResponse{Body: body, DropChunk: drop}
}

func (e *engine) storeSession(session *privacySession, keys ...string) {
	if session == nil || len(keys) == 0 {
		return
	}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneLocked(now)
	for _, key := range keys {
		if entry, ok := e.sessions[key]; ok && entry.session != session {
			e.deleteSessionLocked(entry.session)
		}
	}
	if e.uniqueSessionCountLocked() >= e.cfg.Session.MaxSessions {
		var oldestSession *privacySession
		var oldest time.Time
		for _, entry := range e.sessions {
			if oldestSession == nil || entry.expiresAt.Before(oldest) {
				oldestSession, oldest = entry.session, entry.expiresAt
			}
		}
		e.deleteSessionLocked(oldestSession)
	}
	entry := sessionEntry{session: session, expiresAt: now.Add(time.Duration(e.cfg.Session.TTLSeconds) * time.Second)}
	for _, key := range keys {
		if key != "" {
			e.sessions[key] = entry
		}
	}
}

func (e *engine) takeSession(keys []string, remove bool, markerPayloads ...[]byte) *privacySession {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneLocked(time.Now())
	session := e.findSessionLocked(keys, markerPayloads...)
	if session == nil {
		return nil
	}
	if remove {
		e.deleteSessionLocked(session)
	}
	return session
}

func (e *engine) ensureStream(keys []string, format string, markerPayloads ...[]byte) *streamRestorer {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pruneLocked(time.Now())
	for _, key := range keys {
		if stream := e.streams[key]; stream != nil {
			return stream
		}
	}
	session := e.findSessionLocked(keys, markerPayloads...)
	if session == nil {
		return nil
	}
	for _, stream := range e.streams {
		if stream != nil && stream.session == session {
			return stream
		}
	}
	stream := &streamRestorer{session: session, adapter: adapterForFormat(format)}
	for _, key := range keys {
		if key != "" {
			e.streams[key] = stream
		}
	}
	return stream
}

func (e *engine) findSessionLocked(keys []string, markerPayloads ...[]byte) *privacySession {
	for _, key := range keys {
		if entry, ok := e.sessions[key]; ok && entry.session != nil {
			return entry.session
		}
	}
	return e.findSessionByMarkersLocked(markerPayloads...)
}

func (e *engine) findSessionByMarkersLocked(payloads ...[]byte) *privacySession {
	candidates := markerCandidates(payloads...)
	if len(candidates) == 0 {
		return nil
	}
	seen := make(map[*privacySession]struct{})
	bestScore := 0
	bestSignature := ""
	var best *privacySession
	ambiguous := false
	for _, entry := range e.sessions {
		session := entry.session
		if session == nil {
			continue
		}
		if _, ok := seen[session]; ok {
			continue
		}
		seen[session] = struct{}{}
		session.ensureMarkerIndex()
		score, signature := markerMatchSignature(session, candidates)
		if score == 0 || score < bestScore {
			continue
		}
		if score > bestScore {
			best, bestScore, bestSignature, ambiguous = session, score, signature, false
			continue
		}
		if signature != bestSignature {
			ambiguous = true
		}
	}
	if ambiguous {
		return nil
	}
	return best
}

func markerMatchSignature(session *privacySession, candidates []string) (int, string) {
	var signature strings.Builder
	score := 0
	for _, candidate := range candidates {
		item, ok := session.byMarker[candidate]
		if !ok {
			continue
		}
		score++
		signature.WriteString(candidate)
		signature.WriteByte(0)
		signature.WriteString(item.Original)
		signature.WriteByte(0)
	}
	return score, signature.String()
}

func (e *engine) deleteSessionLocked(session *privacySession) {
	if session == nil {
		return
	}
	for key, entry := range e.sessions {
		if entry.session == session {
			delete(e.sessions, key)
		}
	}
	for key, stream := range e.streams {
		if stream != nil && stream.session == session {
			delete(e.streams, key)
		}
	}
}

func (e *engine) uniqueSessionCountLocked() int {
	seen := make(map[*privacySession]struct{})
	for _, entry := range e.sessions {
		if entry.session != nil {
			seen[entry.session] = struct{}{}
		}
	}
	return len(seen)
}

func (e *engine) pruneLocked(now time.Time) {
	for key, entry := range e.sessions {
		if !entry.expiresAt.After(now) {
			delete(e.sessions, key)
		}
	}
	active := make(map[*privacySession]struct{})
	for _, entry := range e.sessions {
		if entry.session != nil {
			active[entry.session] = struct{}{}
		}
	}
	for key, stream := range e.streams {
		if stream == nil {
			delete(e.streams, key)
			continue
		}
		if _, ok := active[stream.session]; !ok {
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

func requestBodyKey(requestBody []byte) string {
	if len(requestBody) == 0 {
		return ""
	}
	digest := sha256.Sum256(requestBody)
	return "body-" + hex.EncodeToString(digest[:16])
}

func sessionLookupKeys(metadata map[string]any, bodies [][]byte, models ...string) []string {
	keys := make([]string, 0, 1+len(bodies)*(1+len(models)))
	seen := make(map[string]struct{})
	add := func(key string) {
		if key == "" {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	if metadata != nil {
		if value, ok := metadata[cpaRequestIDMetadataKey].(string); ok {
			add(strings.TrimSpace(value))
		}
	}
	for _, body := range bodies {
		add(requestBodyKey(body))
		for _, model := range models {
			if strings.TrimSpace(model) != "" {
				add(requestKey(nil, body, model))
			}
		}
	}
	return keys
}

func firstSessionKey(keys []string, metadata map[string]any, requestBody []byte, model string) string {
	if len(keys) != 0 {
		return keys[0]
	}
	return requestKey(metadata, requestBody, model)
}

var compactMarkerDigestLengths = [...]int{13, 20, 26, 32, 39, 45, 52}

func markerCandidates(payloads ...[]byte) []string {
	seen := make(map[string]struct{})
	for _, payload := range payloads {
		for offset := 0; offset < len(payload); {
			relative := bytes.Index(payload[offset:], []byte(markerLead))
			if relative < 0 {
				break
			}
			start := offset + relative
			remaining := payload[start:]
			switch {
			case bytes.HasPrefix(remaining, []byte(legacyMarkerPrefix)):
				end := len(legacyMarkerPrefix) + 32
				if end <= len(remaining) {
					seen[string(remaining[:end])] = struct{}{}
				}
			case bytes.HasPrefix(remaining, []byte(compactLegacyMarkerPrefix)):
				end := len(compactLegacyMarkerPrefix)
				for end < len(remaining) && isMarkerBase32Char(remaining[end]) {
					end++
				}
				if end < len(remaining) && remaining[end] == '_' && end > len(compactLegacyMarkerPrefix) {
					seen[string(remaining[:end+1])] = struct{}{}
				}
			case bytes.HasPrefix(remaining, []byte(markerPrefix)):
				for _, digestLength := range compactMarkerDigestLengths {
					end := len(markerPrefix) + digestLength
					if end > len(remaining) || !allMarkerBase32(remaining[len(markerPrefix):end]) {
						break
					}
					seen[string(remaining[:end])] = struct{}{}
				}
			}
			offset = start + len(markerLead)
		}
	}
	out := make([]string, 0, len(seen))
	for candidate := range seen {
		out = append(out, candidate)
	}
	sort.Strings(out)
	return out
}

func allMarkerBase32(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, char := range value {
		if !isMarkerBase32Char(char) {
			return false
		}
	}
	return true
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
	sessions := e.uniqueSessionCountLocked()
	streamSet := make(map[*streamRestorer]struct{})
	for _, stream := range e.streams {
		if stream != nil {
			streamSet[stream] = struct{}{}
		}
	}
	streams := len(streamSet)
	e.mu.Unlock()
	return engineStatus{
		Enabled: e.cfg.Enabled, SanitizationEnabled: e.cfg.Sanitization.Enabled,
		PrivacyShieldEnabled: e.cfg.Privacy.Enabled, ActiveSessions: sessions, ActiveStreams: streams,
		SanitizedReplacements: e.sanitizedReplacements.Load(), RedactedMappings: e.redactedMappings.Load(),
		RestoredMarkers: e.restoredMarkers.Load(), Warnings: e.cfg.migrationWarnings(),
	}
}
