package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const markerPrefix = "CPA_RESTORE_SECRET_"

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
	Mappings []mapping
	byKey    map[string]string
	nonce    [16]byte
}

func newPrivacySession() *privacySession {
	session := &privacySession{byKey: make(map[string]string)}
	_, _ = rand.Read(session.nonce[:])
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
	root, err := decodeJSON(body)
	if err != nil {
		return nil, nil, fmt.Errorf("privacy shield requires JSON: %w", err)
	}
	redacted, err := redactValue(ctx, root, cfg, scanner, session)
	if err != nil {
		return nil, nil, err
	}
	if len(session.Mappings) == 0 {
		return session, body, nil
	}
	out, err := marshalJSON(redacted)
	return session, out, err
}

func redactValue(ctx context.Context, value any, cfg privacyShieldConfig, scanner detector, session *privacySession) (any, error) {
	return redactValueForField(ctx, value, "", redactionTraversal{}, cfg, scanner, session)
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

func redactValueForField(ctx context.Context, value any, field string, traversal redactionTraversal, cfg privacyShieldConfig, scanner detector, session *privacySession) (any, error) {
	switch node := value.(type) {
	case map[string]any:
		protocolNode := traversal.payload == payloadProtocolContent && isProtocolContentBlock(node)
		if traversal.payload != payloadArbitrary && (traversal.payload == payloadNone || protocolNode) && isOpaqueProtocolBlock(node) {
			return node, nil
		}
		for key, child := range node {
			protocolSemantics := traversal.payload == payloadNone || protocolNode
			if protocolSemantics && (isOpaqueProtocolValue(node, key) || isProtocolStructuralValue(key, traversal, protocolNode)) {
				continue
			}
			childTraversal := redactionTraversal{payload: nextPayloadMode(node, key, child, traversal.payload, protocolNode)}
			redacted, err := redactValueForField(ctx, child, key, childTraversal, cfg, scanner, session)
			if err != nil {
				return nil, err
			}
			node[key] = redacted
		}
		return node, nil
	case []any:
		for index, child := range node {
			redacted, err := redactValueForField(ctx, child, field, traversal, cfg, scanner, session)
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
		return redactString(ctx, node, cfg.MaxFindings, scanner, session)
	default:
		return value, nil
	}
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

func redactString(ctx context.Context, value string, maxFindings int, scanner detector, session *privacySession) (string, error) {
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
	for _, item := range findings {
		original := value[item.Start:item.End]
		key := item.RuleID + "\x00" + original
		marker, exists := session.byKey[key]
		if !exists {
			if maxFindings > 0 && len(session.Mappings) >= maxFindings {
				continue
			}
			marker = session.newMarker(key)
			session.byKey[key] = marker
			session.Mappings = append(session.Mappings, mapping{Marker: marker, Original: original, RuleID: item.RuleID, Description: item.Description})
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
	hash := sha256.New()
	_, _ = hash.Write(s.nonce[:])
	_, _ = hash.Write([]byte(key))
	return markerPrefix + hex.EncodeToString(hash.Sum(nil)[:16])
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
	restored := append([]byte(nil), body...)
	count := 0
	for _, item := range session.Mappings {
		escaped, _ := json.Marshal(item.Original)
		if len(escaped) >= 2 {
			escaped = escaped[1 : len(escaped)-1]
		}
		n := strings.Count(string(restored), item.Marker)
		if n == 0 {
			continue
		}
		restored = []byte(strings.ReplaceAll(string(restored), item.Marker, string(escaped)))
		count += n
	}
	return restored, count
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
	maxMarkerLen   int
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
	for _, item := range session.Mappings {
		if len(item.Marker) > restorer.maxMarkerLen {
			restorer.maxMarkerLen = len(item.Marker)
		}
	}
	return restorer
}

func (r *contentStreamRestorer) feed(fieldKey, text string) (string, int) {
	return r.feedWithMode(fieldKey, text, false)
}

func (r *contentStreamRestorer) feedJSONString(fieldKey, text string) (string, int) {
	return r.feedWithMode("json:"+fieldKey, text, true)
}

func (r *contentStreamRestorer) feedWithMode(fieldKey, text string, jsonString bool) (string, int) {
	if r == nil || r.session == nil || len(r.session.Mappings) == 0 || r.maxMarkerLen <= 1 || text == "" {
		return text, 0
	}
	carry := r.buffers[fieldKey]
	combined := make([]byte, 0, len(carry)+len(text))
	combined = append(combined, carry...)
	combined = append(combined, text...)
	combined, count := restoreContentBytesWithMode(combined, r.session, jsonString)
	safe := contentTailSafeBoundary(combined, r.maxMarkerLen)
	if safe == len(combined) {
		delete(r.buffers, fieldKey)
		return string(combined), count
	}
	if safe <= 0 {
		r.buffers[fieldKey] = append(carry[:0], combined...)
		return "", count
	}
	out, additional := restoreContentBytesWithMode(combined[:safe], r.session, jsonString)
	r.buffers[fieldKey] = append(carry[:0], combined[safe:]...)
	return string(out), count + additional
}

func restoreContentBytes(body []byte, session *privacySession) ([]byte, int) {
	return restoreContentBytesWithMode(body, session, false)
}

func restoreContentBytesWithMode(body []byte, session *privacySession, jsonString bool) ([]byte, int) {
	if session == nil || len(session.Mappings) == 0 || len(body) == 0 {
		return body, 0
	}
	restored := append([]byte(nil), body...)
	count := 0
	for _, item := range session.Mappings {
		marker := []byte(item.Marker)
		n := bytes.Count(restored, marker)
		if n == 0 {
			continue
		}
		replacement := []byte(item.Original)
		if jsonString {
			encoded, err := json.Marshal(item.Original)
			if err != nil || len(encoded) < 2 {
				continue
			}
			replacement = encoded[1 : len(encoded)-1]
		}
		restored = bytes.ReplaceAll(restored, marker, replacement)
		count += n
	}
	return restored, count
}

func contentTailSafeBoundary(body []byte, maxMarkerLen int) int {
	if len(body) == 0 || maxMarkerLen <= 1 {
		return len(body)
	}
	dangerStart := len(body) - (maxMarkerLen - 1)
	if dangerStart < 0 {
		dangerStart = 0
	}
	prefix := []byte(markerPrefix)
	for index := dangerStart; index < len(body); index++ {
		remaining := body[index:]
		matchLen := len(prefix)
		if matchLen > len(remaining) {
			matchLen = len(remaining)
		}
		if bytes.Equal(remaining[:matchLen], prefix[:matchLen]) {
			return index
		}
	}
	return len(body)
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
	start := len(body)
	for _, item := range session.Mappings {
		marker := []byte(item.Marker)
		max := len(marker) - 1
		if max > len(body) {
			max = len(body)
		}
		for size := max; size > 0; size-- {
			if string(body[len(body)-size:]) == string(marker[:size]) && len(body)-size < start {
				start = len(body) - size
			}
		}
	}
	return start
}

func streamTerminalChunk(body []byte) bool {
	text := string(body)
	return strings.Contains(text, "[DONE]") || terminalFinishReasonPattern.MatchString(text) ||
		strings.Contains(text, `"response.completed"`) || strings.Contains(text, `"message_stop"`)
}

var terminalFinishReasonPattern = regexp.MustCompile(`"finish_reason"\s*:\s*(?:"[^"]+"|true|[1-9][0-9]*)`)
