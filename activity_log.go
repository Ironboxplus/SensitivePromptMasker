package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type hostLogRequest struct {
	HostCallbackID string         `json:"host_callback_id,omitempty"`
	Level          string         `json:"level"`
	Message        string         `json:"message"`
	Fields         map[string]any `json:"fields,omitempty"`
}

var hostLogSender = sendCPASensitiveHostLog

func hostActivityContext(hostCallbackID string) context.Context {
	ctx := context.Background()
	if hostCallbackID == "" {
		return ctx
	}
	return withActivityLogger(ctx, func(event activityEvent) {
		_ = writeHostActivityLog(hostCallbackID, event)
	})
}

func writeHostActivityLog(hostCallbackID string, event activityEvent) error {
	message := fmt.Sprintf(
		"SensitivePromptMasker %s count=%d source=%s target=%s stream=%t",
		safeActivityLogToken(event.Stage), event.Count, safeActivityLogToken(event.SourceFormat),
		safeActivityLogToken(event.ToFormat), event.Stream,
	)
	if rules := formatRuleCounts(event.RuleCounts, 16); rules != "" {
		message += " rules=" + rules
	}
	if event.Elapsed > 0 {
		message += fmt.Sprintf(" elapsed_ms=%.3f", float64(event.Elapsed.Microseconds())/1000.0)
	}
	fields := map[string]any{
		"plugin_id":     "cpa-sensitive",
		"stage":         event.Stage,
		"count":         event.Count,
		"model":         event.Model,
		"source_format": event.SourceFormat,
		"to_format":     event.ToFormat,
		"request_id":    event.RequestID,
		"stream":        event.Stream,
	}
	if len(event.RuleCounts) != 0 {
		fields["rule_counts"] = event.RuleCounts
	}
	if event.Elapsed > 0 {
		fields["elapsed_ms"] = float64(event.Elapsed.Microseconds()) / 1000.0
	}
	payload, err := json.Marshal(hostLogRequest{
		HostCallbackID: hostCallbackID,
		Level:          "info",
		Message:        message,
		Fields:         fields,
	})
	if err != nil {
		return err
	}
	raw, err := hostLogSender(payload)
	if err != nil || len(raw) == 0 {
		return err
	}
	var response envelope
	if err := json.Unmarshal(raw, &response); err != nil {
		return fmt.Errorf("decode host log response: %w", err)
	}
	if !response.OK {
		if response.Error != nil {
			return fmt.Errorf("host log failed: %s", response.Error.Message)
		}
		return fmt.Errorf("host log failed")
	}
	return nil
}

func formatRuleCounts(counts map[string]int, limit int) string {
	if len(counts) == 0 {
		return ""
	}
	type ruleCount struct {
		id    string
		count int
	}
	items := make([]ruleCount, 0, len(counts))
	for ruleID, count := range counts {
		if count <= 0 {
			continue
		}
		items = append(items, ruleCount{id: safeActivityLogToken(ruleID), count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count != items[j].count {
			return items[i].count > items[j].count
		}
		return items[i].id < items[j].id
	})
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	parts := make([]string, 0, limit+1)
	for _, item := range items[:limit] {
		parts = append(parts, fmt.Sprintf("%s:%d", item.id, item.count))
	}
	if limit < len(items) {
		parts = append(parts, fmt.Sprintf("other_rules:%d", len(items)-limit))
	}
	return strings.Join(parts, ",")
}

func safeActivityLogToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	var builder strings.Builder
	for _, char := range value {
		if builder.Len() >= 64 {
			break
		}
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9':
			builder.WriteRune(char)
		case char == '.', char == '_', char == '-', char == '/':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "-"
	}
	return builder.String()
}
