package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// protocolAdapter is the compatibility boundary between CPA interceptor DTOs
// and the plugin's protocol-neutral replacement/privacy core. CPA formats are
// selected at the top level; the core does not import CPA packages.
type protocolAdapter interface {
	SanitizeRequest(any, []orderedReplacement) int
	StreamTerminal([]byte) bool
	RestoreStreamChunk([]byte, *contentStreamRestorer) ([]byte, bool, int)
}

func adapterForFormat(format string) protocolAdapter {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "claude", "anthropic":
		return claudeAdapter{}
	case "codex", "openai-response", "openai-responses", "responses":
		return codexAdapter{}
	default:
		return chatAdapter{}
	}
}

func sanitizeProtocolRequest(root any, rules []orderedReplacement, format string) int {
	return adapterForFormat(format).SanitizeRequest(root, rules)
}

type chatAdapter struct{}

func (chatAdapter) SanitizeRequest(root any, rules []orderedReplacement) int {
	return sanitizeNode(root, rules)
}

func (chatAdapter) StreamTerminal(body []byte) bool {
	text := string(body)
	return strings.Contains(text, "[DONE]") || terminalFinishReasonPattern.MatchString(text)
}

func (chatAdapter) RestoreStreamChunk(body []byte, restorer *contentStreamRestorer) ([]byte, bool, int) {
	return restoreKnownStreamChunk(body, restorer)
}

type claudeAdapter struct{}

func (claudeAdapter) SanitizeRequest(root any, rules []orderedReplacement) int {
	object, ok := root.(map[string]any)
	if !ok {
		return 0
	}
	count := 0
	if system, exists := object["system"]; exists {
		updated, replacements := sanitizeTextContainer(system, rules, true)
		object["system"] = updated
		count += replacements
	}
	count += sanitizeRoleArray(object["messages"], rules, map[string]bool{"system": true, "developer": true, "assistant": true})
	return count
}

func (claudeAdapter) StreamTerminal(body []byte) bool {
	text := string(body)
	return strings.Contains(text, `"message_stop"`) || strings.Contains(text, "[DONE]")
}

func (claudeAdapter) RestoreStreamChunk(body []byte, restorer *contentStreamRestorer) ([]byte, bool, int) {
	return restoreClaudeStreamChunk(body, restorer)
}

type codexAdapter struct{}

func (codexAdapter) SanitizeRequest(root any, rules []orderedReplacement) int {
	object, ok := root.(map[string]any)
	if !ok {
		return 0
	}
	count := 0
	for _, key := range []string{"instructions", "system", "system_instruction"} {
		if value, exists := object[key]; exists {
			updated, replacements := sanitizeTextContainer(value, rules, true)
			object[key] = updated
			count += replacements
		}
	}
	roles := map[string]bool{"system": true, "developer": true, "assistant": true, "model": true}
	count += sanitizeRoleArray(object["input"], rules, roles)
	count += sanitizeRoleArray(object["messages"], rules, roles)
	return count
}

func (codexAdapter) StreamTerminal(body []byte) bool {
	text := string(body)
	return strings.Contains(text, `"response.completed"`) || strings.Contains(text, `"response.done"`) || strings.Contains(text, `"response.failed"`) ||
		strings.Contains(text, `"response.incomplete"`) || strings.Contains(text, "[DONE]")
}

func (codexAdapter) RestoreStreamChunk(body []byte, restorer *contentStreamRestorer) ([]byte, bool, int) {
	return restoreKnownStreamChunk(body, restorer)
}

func restoreKnownStreamChunk(body []byte, restorer *contentStreamRestorer) ([]byte, bool, int) {
	if updated, handled, count := restoreSSEJSONChunk(body, func(event map[string]any) (bool, int) {
		return restoreKnownStreamEvent(event, restorer)
	}); handled {
		return updated, true, count
	}

	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(body)))
	decoder.UseNumber()
	var event map[string]any
	if err := decoder.Decode(&event); err != nil {
		return body, false, 0
	}
	handled, count := restoreKnownStreamEvent(event, restorer)
	if !handled {
		return body, false, 0
	}
	updated, err := json.Marshal(event)
	if err != nil {
		return body, false, 0
	}
	return updated, true, count
}

const maxClaudeThinkingBufferBytes = 1024 * 1024

type claudeThinkingState struct {
	pending     [][]byte
	buffered    int
	signed      bool
	passthrough bool
}

func restoreClaudeStreamChunk(body []byte, restorer *contentStreamRestorer) ([]byte, bool, int) {
	if restorer == nil {
		return body, false, 0
	}
	frames := splitStreamFrames(body)
	if len(frames) == 0 {
		return body, false, 0
	}
	var output []byte
	handledAny, totalCount := false, 0
	for _, frame := range frames {
		event, ok := decodeStreamFrameEvent(frame)
		if !ok {
			output = appendStreamFrame(output, frame)
			continue
		}
		eventType, _ := event["type"].(string)
		index := streamValueKey(event["index"], 0)
		switch eventType {
		case "content_block_start":
			block, _ := event["content_block"].(map[string]any)
			blockType, _ := block["type"].(string)
			if blockType == "thinking" || blockType == "redacted_thinking" {
				restorer.claudeThinking[index] = &claudeThinkingState{}
				handledAny = true
				output = appendStreamFrame(output, frame)
				continue
			}
		case "content_block_delta":
			delta, _ := event["delta"].(map[string]any)
			deltaType, _ := delta["type"].(string)
			switch deltaType {
			case "thinking_delta":
				state := ensureClaudeThinkingState(restorer, index)
				handledAny = true
				if state.passthrough {
					output = appendStreamFrame(output, frame)
					continue
				}
				if state.buffered+len(frame) > maxClaudeThinkingBufferBytes {
					output = appendBufferedStreamFrames(output, state.pending)
					state.pending = nil
					state.buffered = 0
					state.passthrough = true
					output = appendStreamFrame(output, frame)
					continue
				}
				state.pending = append(state.pending, append([]byte(nil), frame...))
				state.buffered += len(frame)
				continue
			case "signature_delta":
				state := ensureClaudeThinkingState(restorer, index)
				state.signed = true
				handledAny = true
				output = appendBufferedStreamFrames(output, state.pending)
				state.pending = nil
				state.buffered = 0
				output = appendStreamFrame(output, frame)
				continue
			}
		case "content_block_stop":
			if state := restorer.claudeThinking[index]; state != nil {
				handledAny = true
				var count int
				output, count = flushClaudeThinkingState(output, index, state, restorer)
				totalCount += count
				delete(restorer.claudeThinking, index)
				output = appendStreamFrame(output, frame)
				continue
			}
		case "message_stop":
			if len(restorer.claudeThinking) != 0 {
				handledAny = true
				keys := make([]string, 0, len(restorer.claudeThinking))
				for key := range restorer.claudeThinking {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					state := restorer.claudeThinking[key]
					var count int
					output, count = flushClaudeThinkingState(output, key, state, restorer)
					totalCount += count
					delete(restorer.claudeThinking, key)
				}
			}
		}

		updated, handled, count := restoreKnownStreamChunk(frame, restorer)
		if handled {
			handledAny = true
			totalCount += count
			output = appendStreamFrame(output, updated)
		} else {
			output = appendStreamFrame(output, frame)
		}
	}
	if !handledAny {
		return body, false, 0
	}
	return output, true, totalCount
}

func ensureClaudeThinkingState(restorer *contentStreamRestorer, index string) *claudeThinkingState {
	state := restorer.claudeThinking[index]
	if state == nil {
		state = &claudeThinkingState{}
		restorer.claudeThinking[index] = state
	}
	return state
}

func flushClaudeThinkingState(output []byte, index string, state *claudeThinkingState, restorer *contentStreamRestorer) ([]byte, int) {
	if state == nil || len(state.pending) == 0 {
		return output, 0
	}
	if state.signed || state.passthrough {
		return appendBufferedStreamFrames(output, state.pending), 0
	}
	totalCount := 0
	for _, frame := range state.pending {
		restored, count := restoreClaudeThinkingFrame(frame, index, restorer)
		output = appendStreamFrame(output, restored)
		totalCount += count
	}
	return output, totalCount
}

func restoreClaudeThinkingFrame(frame []byte, index string, restorer *contentStreamRestorer) ([]byte, int) {
	if bytes.Contains(frame, []byte("data:")) {
		updated, handled, count := restoreSSEJSONChunk(frame, func(event map[string]any) (bool, int) {
			delta, _ := event["delta"].(map[string]any)
			return restoreStreamStringField(delta, "thinking", restorer, "block:"+index+":thinking")
		})
		if handled {
			return updated, count
		}
		return frame, 0
	}
	event, ok := decodeStreamFrameEvent(frame)
	if !ok {
		return frame, 0
	}
	delta, _ := event["delta"].(map[string]any)
	handled, count := restoreStreamStringField(delta, "thinking", restorer, "block:"+index+":thinking")
	if !handled {
		return frame, 0
	}
	updated, err := json.Marshal(event)
	if err != nil {
		return frame, 0
	}
	return updated, count
}

func splitStreamFrames(body []byte) [][]byte {
	if len(body) == 0 {
		return nil
	}
	if bytes.Contains(body, []byte("\r\n\r\n")) {
		return nonEmptyByteParts(bytes.SplitAfter(body, []byte("\r\n\r\n")))
	}
	if bytes.Contains(body, []byte("\n\n")) {
		return nonEmptyByteParts(bytes.SplitAfter(body, []byte("\n\n")))
	}
	return [][]byte{body}
}

func nonEmptyByteParts(parts [][]byte) [][]byte {
	out := parts[:0]
	for _, part := range parts {
		if len(part) != 0 {
			out = append(out, part)
		}
	}
	return out
}

func decodeStreamFrameEvent(frame []byte) (map[string]any, bool) {
	payload := bytes.TrimSpace(frame)
	if bytes.Contains(payload, []byte("data:")) {
		for _, line := range bytes.Split(payload, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			payload = bytes.TrimSpace(line[len("data:"):])
			break
		}
	}
	if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var event map[string]any
	if err := decoder.Decode(&event); err != nil {
		return nil, false
	}
	return event, true
}

func appendBufferedStreamFrames(output []byte, frames [][]byte) []byte {
	for _, frame := range frames {
		output = appendStreamFrame(output, frame)
	}
	return output
}

func appendStreamFrame(output, frame []byte) []byte {
	if len(frame) == 0 {
		return output
	}
	if len(output) != 0 && output[len(output)-1] != '\n' && frame[0] != '\n' {
		output = append(output, '\n')
	}
	return append(output, frame...)
}

func restoreKnownStreamEvent(event map[string]any, restorer *contentStreamRestorer) (bool, int) {
	for _, apply := range []func(map[string]any, *contentStreamRestorer) (bool, int){
		restoreOpenAIStreamEvent,
		restoreClaudeStreamEvent,
		restoreCodexStreamEvent,
	} {
		if handled, count := apply(event, restorer); handled {
			return true, count
		}
	}
	return false, 0
}

func restoreOpenAIStreamEvent(event map[string]any, restorer *contentStreamRestorer) (bool, int) {
	choices, ok := event["choices"].([]any)
	if !ok {
		return false, 0
	}
	handled, count := false, 0
	for choiceOffset, rawChoice := range choices {
		choice, ok := rawChoice.(map[string]any)
		if !ok {
			continue
		}
		choiceKey := streamValueKey(choice["index"], choiceOffset)
		delta, ok := choice["delta"].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"content", "reasoning", "reasoning_content"} {
			fieldHandled, fieldCount := restoreStreamStringField(delta, field, restorer, "choice:"+choiceKey+":"+field)
			handled = handled || fieldHandled
			count += fieldCount
		}
		toolCalls, _ := delta["tool_calls"].([]any)
		for toolOffset, rawTool := range toolCalls {
			tool, ok := rawTool.(map[string]any)
			if !ok {
				continue
			}
			function, ok := tool["function"].(map[string]any)
			if !ok {
				continue
			}
			toolKey := streamValueKey(tool["index"], toolOffset)
			fieldHandled, fieldCount := restoreStreamJSONStringField(function, "arguments", restorer, "choice:"+choiceKey+":tool:"+toolKey+":arguments")
			handled = handled || fieldHandled
			count += fieldCount
		}
		if functionCall, ok := delta["function_call"].(map[string]any); ok {
			fieldHandled, fieldCount := restoreStreamJSONStringField(functionCall, "arguments", restorer, "choice:"+choiceKey+":function_call:arguments")
			handled = handled || fieldHandled
			count += fieldCount
		}
	}
	return handled, count
}

func restoreClaudeStreamEvent(event map[string]any, restorer *contentStreamRestorer) (bool, int) {
	eventType, _ := event["type"].(string)
	if eventType == "content_block_start" {
		if block, ok := event["content_block"].(map[string]any); ok {
			// Claude can put a complete tool_use input in content_block_start.
			// CPA may deliver that frame together with a later delta in the same
			// callback, so it must be restored here rather than relying on the
			// whole-chunk JSON fallback.
			if isOpaqueProtocolBlock(block) {
				return true, 0
			}
			restored, count := restoreJSONValue(block, "content_block", restorer.session)
			if updated, ok := restored.(map[string]any); ok {
				event["content_block"] = updated
			}
			return true, count
		}
	}
	index := streamValueKey(event["index"], 0)
	delta, ok := event["delta"].(map[string]any)
	if !ok {
		return restoreStreamStringField(event, "completion", restorer, "completion")
	}
	handled, count := false, 0
	for _, field := range []string{"text"} {
		fieldHandled, fieldCount := restoreStreamStringField(delta, field, restorer, "block:"+index+":"+field)
		handled = handled || fieldHandled
		count += fieldCount
	}
	if _, exists := delta["thinking"].(string); exists {
		handled = true
	}
	if _, exists := delta["signature"].(string); exists {
		handled = true
	}
	fieldHandled, fieldCount := restoreStreamJSONStringField(delta, "partial_json", restorer, "block:"+index+":partial_json")
	handled = handled || fieldHandled
	count += fieldCount
	return handled, count
}

func restoreCodexStreamEvent(event map[string]any, restorer *contentStreamRestorer) (bool, int) {
	eventType, _ := event["type"].(string)
	if !strings.HasPrefix(eventType, "response.") {
		return false, 0
	}
	if !strings.Contains(eventType, ".delta") {
		_, count := restoreJSONValue(event, "", restorer.session)
		return true, count
	}
	key := strings.Join([]string{
		eventType,
		streamValueKey(event["item_id"], 0),
		streamValueKey(event["call_id"], 0),
		streamValueKey(event["output_index"], 0),
		streamValueKey(event["content_index"], 0),
	}, ":")
	if strings.Contains(eventType, "function_call_arguments") {
		return restoreStreamJSONStringField(event, "delta", restorer, key)
	}
	return restoreStreamStringField(event, "delta", restorer, key)
}

func restoreSSEJSONChunk(body []byte, apply func(map[string]any) (bool, int)) ([]byte, bool, int) {
	lines := bytes.Split(body, []byte("\n"))
	handledAny, totalCount := false, 0
	for index, originalLine := range lines {
		line := originalLine
		hasCR := len(line) > 0 && line[len(line)-1] == '\r'
		if hasCR {
			line = line[:len(line)-1]
		}
		trimmed := bytes.TrimLeft(line, " \t")
		if !bytes.HasPrefix(trimmed, []byte("data:")) {
			continue
		}
		dataOffset := len(line) - len(trimmed) + len("data:")
		payloadOffset := dataOffset
		if payloadOffset < len(line) && line[payloadOffset] == ' ' {
			payloadOffset++
		}
		payload := bytes.TrimSpace(line[payloadOffset:])
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.UseNumber()
		var event map[string]any
		if err := decoder.Decode(&event); err != nil {
			continue
		}
		handled, count := apply(event)
		if !handled {
			continue
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			continue
		}
		updated := make([]byte, 0, payloadOffset+len(encoded)+1)
		updated = append(updated, line[:payloadOffset]...)
		updated = append(updated, encoded...)
		if hasCR {
			updated = append(updated, '\r')
		}
		lines[index] = updated
		handledAny = true
		totalCount += count
	}
	if !handledAny {
		return body, false, 0
	}
	return bytes.Join(lines, []byte("\n")), true, totalCount
}

func restoreStreamStringField(object map[string]any, field string, restorer *contentStreamRestorer, fieldKey string) (bool, int) {
	text, ok := object[field].(string)
	if !ok {
		return false, 0
	}
	restored, count := restorer.feed(fieldKey, text)
	object[field] = restored
	return true, count
}

func restoreStreamJSONStringField(object map[string]any, field string, restorer *contentStreamRestorer, fieldKey string) (bool, int) {
	text, ok := object[field].(string)
	if !ok {
		return false, 0
	}
	restored, count := restorer.feedJSONString(fieldKey, text)
	object[field] = restored
	return true, count
}

func streamValueKey(value any, fallback int) string {
	if value == nil {
		return fmt.Sprintf("%d", fallback)
	}
	return fmt.Sprint(value)
}

func sanitizeRoleArray(value any, rules []orderedReplacement, allowedRoles map[string]bool) int {
	items, ok := value.([]any)
	if !ok {
		return 0
	}
	count := 0
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		role, _ := item["role"].(string)
		if !allowedRoles[strings.ToLower(strings.TrimSpace(role))] {
			continue
		}
		for _, key := range []string{"content", "text", "parts", "reasoning", "reasoning_content"} {
			if value, exists := item[key]; exists {
				updated, replacements := sanitizeTextContainer(value, rules, true)
				item[key] = updated
				count += replacements
			}
		}
	}
	return count
}
