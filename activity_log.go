package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	payload, err := json.Marshal(hostLogRequest{
		HostCallbackID: hostCallbackID,
		Level:          "info",
		Message: fmt.Sprintf(
			"SensitivePromptMasker %s count=%d source=%s target=%s stream=%t",
			safeActivityLogToken(event.Stage), event.Count, safeActivityLogToken(event.SourceFormat),
			safeActivityLogToken(event.ToFormat), event.Stream,
		),
		Fields: map[string]any{
			"plugin_id":     "cpa-sensitive",
			"stage":         event.Stage,
			"count":         event.Count,
			"model":         event.Model,
			"source_format": event.SourceFormat,
			"to_format":     event.ToFormat,
			"request_id":    event.RequestID,
			"stream":        event.Stream,
		},
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
