package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	markerPrefix              = "CPAS"
	compactLegacyMarkerPrefix = "CPA_S_"
	legacyMarkerPrefix        = "CPA_RESTORE_SECRET_"
	markerLead                = "CPA"
)

var markerEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type finding struct {
	Start       int
	End         int
	RuleID      string
	Description string
}

type detector interface {
	DetectString(context.Context, string) ([]finding, error)
}

type mapping struct {
	Marker      string
	Original    string
	RuleID      string
	Description string
}

type privacySession struct {
	Mappings     []mapping
	byKey        map[string]string
	byMarker     map[string]mapping
	markerKeys   map[string]string
	RuleCounts   map[string]int
	maxMarkerLen int
	indexMu      sync.Mutex
	indexReady   atomic.Bool
}

func newPrivacySession() *privacySession {
	session := &privacySession{
		byKey:      make(map[string]string),
		byMarker:   make(map[string]mapping),
		markerKeys: make(map[string]string),
		RuleCounts: make(map[string]int),
	}
	return session
}

func redactJSON(ctx context.Context, body []byte, cfg privacyShieldConfig, scanner detector) (*privacySession, []byte, error) {
	session := newPrivacySession()
	if !cfg.Enabled || len(body) == 0 || len(body) > cfg.MaxBodyBytes {
		return session, body, nil
	}
	if scanner == nil {
		return nil, nil, errors.New("privacy shield detector is unavailable")
	}
	originalRoot, err := decodeJSON(body)
	if err != nil {
		return nil, nil, fmt.Errorf("privacy shield requires JSON: %w", err)
	}
	redactionRoot, err := decodeJSON(body)
	if err != nil {
		return nil, nil, fmt.Errorf("privacy shield requires JSON: %w", err)
	}
	redacted, err := redactValue(ctx, redactionRoot, cfg, scanner, session)
	if err != nil {
		return nil, nil, err
	}
	session.finalizeMarkerIndex()
	if len(session.Mappings) == 0 {
		return session, body, nil
	}
	out, err := rewriteJSONStrings(body, originalRoot, redacted)
	if err == nil {
		return session, out, nil
	}
	// Duplicate object keys and other unusual-but-valid JSON shapes cannot be
	// mapped back to unique semantic paths. Preserve the historical safe
	// fallback instead of rejecting a request that the previous implementation
	// accepted.
	out, marshalErr := marshalJSON(redacted)
	if marshalErr != nil {
		return nil, nil, fmt.Errorf("privacy JSON rewrite failed: %v; fallback marshal failed: %w", err, marshalErr)
	}
	return session, out, nil
}

func redactValue(ctx context.Context, value any, cfg privacyShieldConfig, scanner detector, session *privacySession) (any, error) {
	return redactValueForField(ctx, value, "", "$", redactionTraversal{}, cfg, scanner, session)
}

type payloadMode uint8

const (
	payloadNone payloadMode = iota
	payloadArbitrary
	payloadProtocolContent
)

type redactionTraversal struct {
	payload payloadMode
}

func redactValueForField(ctx context.Context, value any, field, path string, traversal redactionTraversal, cfg privacyShieldConfig, scanner detector, session *privacySession) (any, error) {
	switch node := value.(type) {
	case map[string]any:
		protocolNode := traversal.payload == payloadProtocolContent && isProtocolContentBlock(node)
		if traversal.payload != payloadArbitrary && (traversal.payload == payloadNone || protocolNode) && isOpaqueProtocolBlock(node) {
			return node, nil
		}
		keys := make([]string, 0, len(node))
		for key := range node {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := node[key]
			protocolSemantics := traversal.payload == payloadNone || protocolNode
			if protocolSemantics && (isOpaqueProtocolValue(node, key) || isProtocolStructuralValue(key, traversal, protocolNode)) {
				continue
			}
			childTraversal := redactionTraversal{payload: nextPayloadMode(node, key, child, traversal.payload, protocolNode)}
			redacted, err := redactValueForField(ctx, child, key, appendJSONPath(path, key), childTraversal, cfg, scanner, session)
			if err != nil {
				return nil, err
			}
			node[key] = redacted
		}
		return node, nil
	case []any:
		for index, child := range node {
			redacted, err := redactValueForField(ctx, child, field, path+"/"+strconv.Itoa(index), traversal, cfg, scanner, session)
			if err != nil {
				return nil, err
			}
			node[index] = redacted
		}
		return node, nil
	case string:
		if len(node) > cfg.MaxStringBytes {
			return node, nil
		}
		return redactString(ctx, node, path, cfg.MaxFindings, scanner, session)
	default:
		return value, nil
	}
}

func appendJSONPath(path, key string) string {
	key = strings.ReplaceAll(key, "~", "~0")
	key = strings.ReplaceAll(key, "/", "~1")
	return path + "/" + key
}

func isProtocolStructuralValue(field string, traversal redactionTraversal, protocolNode bool) bool {
	if traversal.payload == payloadNone {
		return isProtocolStructuralField(field)
	}
	return traversal.payload == payloadProtocolContent && protocolNode && isProtocolStructuralField(field)
}

func nextPayloadMode(parent map[string]any, field string, child any, current payloadMode, protocolNode bool) payloadMode {
	if current == payloadArbitrary {
		return payloadArbitrary
	}
	field = strings.ToLower(strings.TrimSpace(field))
	valueType, _ := parent["type"].(string)
	role, _ := parent["role"].(string)
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "tool_use":
		if field == "input" {
			return payloadArbitrary
		}
	case "tool_result":
		if field == "content" {
			return payloadProtocolContent
		}
	case "function_call_output", "custom_tool_call_output":
		if field == "output" {
			return payloadProtocolContent
		}
	case "custom_tool_call":
		if field == "input" {
			return payloadArbitrary
		}
	}
	if strings.EqualFold(strings.TrimSpace(role), "tool") && field == "content" {
		return payloadProtocolContent
	}
	if current == payloadProtocolContent {
		if !protocolNode {
			return payloadArbitrary
		}
		switch field {
		case "content", "source":
			return payloadProtocolContent
		default:
			if _, ok := child.(map[string]any); ok {
				return payloadArbitrary
			}
		}
	}
	return current
}

func isProtocolContentType(valueType string) bool {
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "text", "input_text", "output_text", "message",
		"image", "input_image", "image_url", "document", "file", "input_file", "input_audio", "audio", "video_url",
		"tool_use", "tool_result", "tool_reference", "server_tool_use", "web_search_tool_result",
		"function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output",
		"thinking", "redacted_thinking", "reasoning", "encrypted_content",
		"base64", "url":
		return true
	default:
		return false
	}
}

func isProtocolContentBlock(node map[string]any) bool {
	valueType, _ := node["type"].(string)
	if !isProtocolContentType(valueType) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "text", "input_text", "output_text":
		_, ok := node["text"]
		return ok
	case "image":
		_, source := node["source"]
		_, url := node["url"]
		return source || url
	case "input_image":
		_, ok := node["image_url"]
		return ok
	case "image_url":
		_, wrapped := node["image_url"]
		_, direct := node["url"]
		return wrapped || direct
	case "document":
		_, source := node["source"]
		_, data := node["data"]
		return source || data
	case "file", "input_file":
		_, wrapped := node["file"]
		_, data := node["file_data"]
		_, url := node["file_url"]
		_, id := node["file_id"]
		return wrapped || data || url || id
	case "input_audio", "audio":
		_, wrapped := node["input_audio"]
		_, data := node["data"]
		return wrapped || data
	case "video_url":
		_, wrapped := node["video_url"]
		_, direct := node["url"]
		return wrapped || direct
	case "tool_use":
		_, name := node["name"]
		_, input := node["input"]
		return name && input
	case "tool_result":
		_, ok := node["tool_use_id"]
		return ok
	case "tool_reference":
		_, ok := node["tool_name"]
		return ok
	case "function_call":
		_, name := node["name"]
		_, arguments := node["arguments"]
		return name && arguments
	case "function_call_output", "custom_tool_call_output":
		_, callID := node["call_id"]
		_, output := node["output"]
		return callID && output
	case "custom_tool_call":
		_, name := node["name"]
		_, input := node["input"]
		return name && input
	case "thinking":
		_, thinking := node["thinking"]
		_, signature := node["signature"]
		return thinking || signature
	case "redacted_thinking":
		_, ok := node["data"]
		return ok
	case "reasoning":
		_, summary := node["summary"]
		_, encrypted := node["encrypted_content"]
		return summary || encrypted
	case "encrypted_content":
		_, ok := node["encrypted_content"]
		return ok
	case "base64":
		_, ok := node["data"]
		return ok
	case "url":
		_, ok := node["url"]
		return ok
	case "message":
		_, role := node["role"]
		_, content := node["content"]
		return role && content
	default:
		return true
	}
}

func isProtocolStructuralField(field string) bool {
	field = strings.ToLower(strings.TrimSpace(field))
	if field == "" {
		return false
	}
	switch field {
	case "type", "role", "model", "object", "status", "name", "format", "method",
		"tool_name", "signature", "encrypted_content",
		"finish_reason", "stop_reason", "stop_sequence", "service_tier", "reasoning_effort", "verbosity",
		"protocol", "source_format", "to_format":
		return true
	}
	return field == "id" || strings.HasSuffix(field, "_id") || strings.HasSuffix(field, "_type") ||
		strings.HasSuffix(field, "_format") || strings.HasSuffix(field, "_reason") || strings.HasSuffix(field, "_status")
}

func isOpaqueProtocolValue(parent map[string]any, field string) bool {
	field = strings.ToLower(strings.TrimSpace(field))
	valueType, _ := parent["type"].(string)
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "base64", "redacted_thinking", "encrypted", "encrypted_content":
		return field == "data" || field == "encrypted_content"
	case "input_image":
		return field == "image_url" || field == "file_id"
	case "input_file":
		return field == "file_data" || field == "file_url" || field == "file_id"
	case "image_url":
		return field == "url" || field == "image_url" || field == "file_id"
	case "image", "document":
		return field == "data" || field == "url" || field == "image_url" || field == "file_data" || field == "file_url" || field == "file_id"
	case "file":
		return field == "file" || field == "data" || field == "url" || field == "file_data" || field == "file_url" || field == "file_id"
	case "input_audio", "audio":
		return field == "input_audio" || field == "data"
	case "video_url":
		return field == "video_url" || field == "url"
	case "url":
		return field == "url"
	default:
		return field == "signature" || field == "encrypted_content"
	}
}

func isOpaqueProtocolBlock(node map[string]any) bool {
	valueType, _ := node["type"].(string)
	switch strings.ToLower(strings.TrimSpace(valueType)) {
	case "redacted_thinking", "encrypted_content":
		return true
	case "thinking":
		signature, _ := node["signature"].(string)
		return strings.TrimSpace(signature) != ""
	case "reasoning":
		encryptedContent, _ := node["encrypted_content"].(string)
		return strings.TrimSpace(encryptedContent) != ""
	default:
		return false
	}
}

func redactString(ctx context.Context, value, path string, maxFindings int, scanner detector, session *privacySession) (string, error) {
	findings, err := scanner.DetectString(ctx, value)
	if err != nil {
		return "", err
	}
	findings = normalizeFindings(value, findings)
	if len(findings) == 0 {
		return value, nil
	}
	var builder strings.Builder
	last := 0
	for findingIndex, item := range findings {
		original := value[item.Start:item.End]
		key := path + "\x00" + item.RuleID + "\x00" + strconv.Itoa(findingIndex)
		marker, exists := session.byKey[key]
		if !exists {
			if maxFindings > 0 && len(session.Mappings) >= maxFindings {
				continue
			}
			marker = session.newMarker(key)
			session.byKey[key] = marker
			session.addMapping(mapping{Marker: marker, Original: original, RuleID: item.RuleID, Description: item.Description})
		}
		builder.WriteString(value[last:item.Start])
		builder.WriteString(marker)
		last = item.End
	}
	if last == 0 {
		return value, nil
	}
	builder.WriteString(value[last:])
	return builder.String(), nil
}

func (s *privacySession) newMarker(key string) string {
	if s == nil {
		return ""
	}
	digest := sha256.Sum256([]byte("cpa-sensitive-marker-v1\x00" + key))
	if s.markerKeys == nil {
		s.markerKeys = make(map[string]string)
	}
	for digestBytes := 8; digestBytes <= len(digest); digestBytes += 4 {
		marker := markerPrefix + markerEncoding.EncodeToString(digest[:digestBytes])
		if existingKey, exists := s.markerKeys[marker]; !exists || existingKey == key {
			s.markerKeys[marker] = key
			return marker
		}
	}
	panic("privacy marker HMAC collision")
}

func (s *privacySession) addMapping(item mapping) {
	if s == nil || item.Marker == "" {
		return
	}
	s.Mappings = append(s.Mappings, item)
	if s.byMarker == nil {
		s.byMarker = make(map[string]mapping)
	}
	s.byMarker[item.Marker] = item
	if len(item.Marker) > s.maxMarkerLen {
		s.maxMarkerLen = len(item.Marker)
	}
	if item.RuleID != "" {
		if s.RuleCounts == nil {
			s.RuleCounts = make(map[string]int)
		}
		s.RuleCounts[item.RuleID]++
	}
}

func (s *privacySession) finalizeMarkerIndex() {
	if s == nil {
		return
	}
	s.ensureMarkerIndex()
}

func (s *privacySession) ensureMarkerIndex() {
	if s == nil || s.indexReady.Load() {
		return
	}
	s.indexMu.Lock()
	defer s.indexMu.Unlock()
	if s.indexReady.Load() {
		return
	}
	byMarker := make(map[string]mapping, len(s.Mappings))
	ruleCounts := make(map[string]int)
	maxMarkerLen := 0
	for _, item := range s.Mappings {
		if item.Marker == "" {
			continue
		}
		byMarker[item.Marker] = item
		if len(item.Marker) > maxMarkerLen {
			maxMarkerLen = len(item.Marker)
		}
		if item.RuleID != "" {
			ruleCounts[item.RuleID]++
		}
	}
	s.byMarker = byMarker
	s.RuleCounts = ruleCounts
	s.maxMarkerLen = maxMarkerLen
	s.indexReady.Store(true)
}

func (s *privacySession) ruleCountsSnapshot() map[string]int {
	if s == nil {
		return nil
	}
	s.ensureMarkerIndex()
	if len(s.RuleCounts) == 0 {
		return nil
	}
	out := make(map[string]int, len(s.RuleCounts))
	for ruleID, count := range s.RuleCounts {
		out[ruleID] = count
	}
	return out
}

func normalizeFindings(value string, findings []finding) []finding {
	valid := make([]finding, 0, len(findings))
	for _, item := range findings {
		if item.Start < 0 || item.End <= item.Start || item.End > len(value) {
			continue
		}
		valid = append(valid, item)
	}
	sort.SliceStable(valid, func(i, j int) bool {
		if valid[i].Start == valid[j].Start {
			return valid[i].End-valid[i].Start > valid[j].End-valid[j].Start
		}
		return valid[i].Start < valid[j].Start
	})
	out := valid[:0]
	lastEnd := -1
	for _, item := range valid {
		if item.Start < lastEnd {
			continue
		}
		out = append(out, item)
		lastEnd = item.End
	}
	return out
}

func restoreJSONBytes(body []byte, session *privacySession) ([]byte, int) {
	if session == nil || len(session.Mappings) == 0 || len(body) == 0 {
		return body, 0
	}
	root, err := decodeJSON(body)
	if err == nil {
		restoredRoot, count := restoreJSONValue(root, "", session)
		if count == 0 {
			return body, 0
		}
		if restored, marshalErr := marshalJSON(restoredRoot); marshalErr == nil {
			return restored, count
		}
	}
	return restoreRawJSONBytes(body, session)
}

func restoreJSONValue(value any, field string, session *privacySession) (any, int) {
	return restoreJSONValueWithMode(value, field, payloadNone, session)
}

func restoreJSONValueWithMode(value any, field string, mode payloadMode, session *privacySession) (any, int) {
	switch node := value.(type) {
	case map[string]any:
		protocolNode := mode == payloadProtocolContent && isProtocolContentBlock(node)
		if mode != payloadArbitrary && (mode == payloadNone || protocolNode) && isOpaqueProtocolBlock(node) {
			return node, 0
		}
		count := 0
		for key, child := range node {
			childMode := nextPayloadMode(node, key, child, mode, protocolNode)
			if text, ok := child.(string); ok {
				restored, childCount := restoreContentBytesWithMode([]byte(text), session, isEmbeddedJSONStringValue(node, field, key, mode, protocolNode))
				node[key] = string(restored)
				count += childCount
				continue
			}
			restored, childCount := restoreJSONValueWithMode(child, key, childMode, session)
			node[key] = restored
			count += childCount
		}
		return node, count
	case []any:
		count := 0
		for index, child := range node {
			restored, childCount := restoreJSONValueWithMode(child, field, mode, session)
			node[index] = restored
			count += childCount
		}
		return node, count
	case string:
		restored, count := restoreContentBytesWithMode([]byte(node), session, false)
		return string(restored), count
	default:
		return value, 0
	}
}

func isEmbeddedJSONStringValue(parent map[string]any, containerField, field string, mode payloadMode, protocolNode bool) bool {
	if mode == payloadArbitrary || (mode == payloadProtocolContent && !protocolNode) {
		return false
	}
	field = strings.ToLower(strings.TrimSpace(field))
	containerField = strings.ToLower(strings.TrimSpace(containerField))
	valueType, _ := parent["type"].(string)
	valueType = strings.ToLower(strings.TrimSpace(valueType))
	if field == "partial_json" {
		return valueType == "input_json_delta"
	}
	if field != "arguments" {
		return false
	}
	return containerField == "function" || containerField == "function_call" ||
		valueType == "function_call" || strings.Contains(valueType, "function_call_arguments")
}

func restoreRawJSONBytes(body []byte, session *privacySession) ([]byte, int) {
	return restoreContentBytesWithMode(body, session, true)
}

type streamRestorer struct {
	carry   []byte
	session *privacySession
	adapter protocolAdapter
	content *contentStreamRestorer
}

func (r *streamRestorer) feed(chunk []byte) ([]byte, bool, int) {
	if r == nil || r.session == nil || len(r.session.Mappings) == 0 {
		return chunk, false, 0
	}
	if r.adapter != nil {
		if r.content == nil {
			r.content = newContentStreamRestorer(r.session)
		}
		if body, handled, count := r.adapter.RestoreStreamChunk(chunk, r.content); handled {
			return body, len(body) == 0, count
		}
	}
	combined := append(append([]byte(nil), r.carry...), chunk...)
	r.carry = nil
	terminal := r.streamTerminal(combined)
	safe := len(combined)
	if !terminal {
		safe = partialMarkerStart(combined, r.session)
	}
	if safe < len(combined) {
		r.carry = append(r.carry, combined[safe:]...)
	}
	out, count := restoreJSONBytes(combined[:safe], r.session)
	return out, len(out) == 0, count
}

type contentStreamRestorer struct {
	session        *privacySession
	buffers        map[string][]byte
	claudeThinking map[string]*claudeThinkingState
}

func newContentStreamRestorer(session *privacySession) *contentStreamRestorer {
	restorer := &contentStreamRestorer{
		session: session, buffers: make(map[string][]byte), claudeThinking: make(map[string]*claudeThinkingState),
	}
	if session == nil {
		return restorer
	}
	session.ensureMarkerIndex()
	return restorer
}

func (r *contentStreamRestorer) feed(fieldKey, text string) (string, int) {
	return r.feedWithMode(fieldKey, text, false)
}

func (r *contentStreamRestorer) feedJSONString(fieldKey, text string) (string, int) {
	return r.feedWithMode("json:"+fieldKey, text, true)
}

func (r *contentStreamRestorer) feedWithMode(fieldKey, text string, jsonString bool) (string, int) {
	if r == nil || r.session == nil || len(r.session.Mappings) == 0 || text == "" {
		return text, 0
	}
	carry := r.buffers[fieldKey]
	combined := make([]byte, 0, len(carry)+len(text))
	combined = append(combined, carry...)
	combined = append(combined, text...)
	safe := partialMarkerStart(combined, r.session)
	if safe == len(combined) {
		delete(r.buffers, fieldKey)
		out, count := restoreContentBytesWithMode(combined, r.session, jsonString)
		return string(out), count
	}
	if safe <= 0 {
		r.buffers[fieldKey] = append(carry[:0], combined...)
		return "", 0
	}
	out, count := restoreContentBytesWithMode(combined[:safe], r.session, jsonString)
	r.buffers[fieldKey] = append(carry[:0], combined[safe:]...)
	return string(out), count
}

func restoreContentBytes(body []byte, session *privacySession) ([]byte, int) {
	return restoreContentBytesWithMode(body, session, false)
}

func restoreContentBytesWithMode(body []byte, session *privacySession, jsonString bool) ([]byte, int) {
	if session == nil || len(session.Mappings) == 0 || len(body) == 0 {
		return body, 0
	}
	session.ensureMarkerIndex()
	if len(session.byMarker) == 0 {
		return body, 0
	}

	searchAt := 0
	lastWrite := 0
	count := 0
	var restored []byte
	lead := []byte(markerLead)
	for searchAt < len(body) {
		relative := bytes.Index(body[searchAt:], lead)
		if relative < 0 {
			break
		}
		start := searchAt + relative
		item, end, ok := session.matchMarkerAt(body, start)
		if !ok {
			searchAt = start + len(lead)
			continue
		}
		if restored == nil {
			restored = make([]byte, 0, len(body))
		}
		restored = append(restored, body[lastWrite:start]...)
		replacement := []byte(item.Original)
		if jsonString {
			encoded, err := json.Marshal(item.Original)
			if err != nil || len(encoded) < 2 {
				searchAt = end
				continue
			}
			replacement = encoded[1 : len(encoded)-1]
		}
		restored = append(restored, replacement...)
		lastWrite = end
		searchAt = end
		count++
	}
	if count == 0 {
		return body, 0
	}
	restored = append(restored, body[lastWrite:]...)
	return restored, count
}

func (s *privacySession) matchMarkerAt(body []byte, start int) (mapping, int, bool) {
	if s == nil || start < 0 || start >= len(body) {
		return mapping{}, start, false
	}
	remaining := body[start:]
	if bytes.HasPrefix(remaining, []byte(legacyMarkerPrefix)) {
		end := start + len(legacyMarkerPrefix) + 32
		if end <= len(body) {
			if item, ok := s.byMarker[string(body[start:end])]; ok {
				return item, end, true
			}
		}
	}
	if bytes.HasPrefix(remaining, []byte(compactLegacyMarkerPrefix)) {
		for end := start + len(compactLegacyMarkerPrefix); end < len(body) && end-start <= s.maxMarkerLen; end++ {
			char := body[end]
			if char == '_' {
				candidateEnd := end + 1
				if item, ok := s.byMarker[string(body[start:candidateEnd])]; ok {
					return item, candidateEnd, true
				}
				break
			}
			if !isMarkerBase32Char(char) {
				break
			}
		}
	}
	if bytes.HasPrefix(remaining, []byte(markerPrefix)) {
		for end := start + len(markerPrefix) + 1; end <= len(body) && end-start <= s.maxMarkerLen; end++ {
			if !isMarkerBase32Char(body[end-1]) {
				break
			}
			if item, ok := s.byMarker[string(body[start:end])]; ok {
				return item, end, true
			}
		}
	}
	limit := start + s.maxMarkerLen
	if limit > len(body) {
		limit = len(body)
	}
	for end := start + len(markerLead); end <= limit; end++ {
		if item, ok := s.byMarker[string(body[start:end])]; ok {
			return item, end, true
		}
	}
	return mapping{}, start, false
}

func (r *streamRestorer) streamTerminal(body []byte) bool {
	if r != nil && r.adapter != nil {
		return r.adapter.StreamTerminal(body)
	}
	return streamTerminalChunk(body)
}

func (r *streamRestorer) flush() ([]byte, int) {
	if r == nil || len(r.carry) == 0 {
		return nil, 0
	}
	out, count := restoreJSONBytes(r.carry, r.session)
	r.carry = nil
	return out, count
}

func partialMarkerStart(body []byte, session *privacySession) int {
	if session == nil || len(body) == 0 {
		return len(body)
	}
	session.ensureMarkerIndex()
	if session.maxMarkerLen <= 1 {
		return len(body)
	}
	dangerStart := len(body) - (session.maxMarkerLen - 1)
	if dangerStart < 0 {
		dangerStart = 0
	}
	for start := dangerStart; start < len(body); start++ {
		remaining := body[start:]
		if _, end, ok := session.matchMarkerAt(body, start); ok && end <= len(body) {
			continue
		}
		if session.possibleMarkerPrefix(remaining) {
			return start
		}
	}
	return len(body)
}

func (s *privacySession) possibleMarkerPrefix(remaining []byte) bool {
	if s == nil || len(remaining) == 0 || len(remaining) >= s.maxMarkerLen {
		return false
	}
	compactPrefix := []byte(markerPrefix)
	if bytes.HasPrefix(compactPrefix, remaining) {
		return true
	}
	if bytes.HasPrefix(remaining, compactPrefix) {
		suffix := remaining[len(compactPrefix):]
		if len(suffix) == 0 {
			return true
		}
		for _, char := range suffix {
			if !isMarkerBase32Char(byte(char)) {
				return false
			}
		}
		return true
	}
	oldCompactPrefix := []byte(compactLegacyMarkerPrefix)
	if bytes.HasPrefix(oldCompactPrefix, remaining) {
		return true
	}
	if bytes.HasPrefix(remaining, oldCompactPrefix) {
		suffix := remaining[len(oldCompactPrefix):]
		if len(suffix) == 0 {
			return true
		}
		for _, char := range suffix {
			if char == '_' {
				return true
			}
			if !isMarkerBase32Char(byte(char)) {
				return false
			}
		}
		return true
	}
	legacyPrefix := []byte(legacyMarkerPrefix)
	if bytes.HasPrefix(legacyPrefix, remaining) {
		return true
	}
	if !bytes.HasPrefix(remaining, legacyPrefix) {
		return false
	}
	hexSuffix := remaining[len(legacyPrefix):]
	if len(hexSuffix) >= 32 {
		return false
	}
	for _, char := range hexSuffix {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F') {
			continue
		}
		return false
	}
	return true
}

func isMarkerBase32Char(char byte) bool {
	return (char >= 'A' && char <= 'Z') || (char >= '2' && char <= '7')
}

func streamTerminalChunk(body []byte) bool {
	text := string(body)
	return strings.Contains(text, "[DONE]") || terminalFinishReasonPattern.MatchString(text) ||
		strings.Contains(text, `"response.completed"`) || strings.Contains(text, `"message_stop"`)
}

var terminalFinishReasonPattern = regexp.MustCompile(`"finish_reason"\s*:\s*(?:"[^"]+"|true|[1-9][0-9]*)`)
