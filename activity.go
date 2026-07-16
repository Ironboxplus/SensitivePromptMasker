package main

import (
	"context"
	"time"
)

type activityEvent struct {
	Stage        string
	Model        string
	SourceFormat string
	ToFormat     string
	RequestID    string
	Count        int
	Stream       bool
	RuleCounts   map[string]int
	Elapsed      time.Duration
}

type activityLogger func(activityEvent)

type activityLoggerContextKey struct{}

func withActivityLogger(ctx context.Context, logger activityLogger) context.Context {
	if logger == nil {
		return ctx
	}
	return context.WithValue(ctx, activityLoggerContextKey{}, logger)
}

func emitActivity(ctx context.Context, event activityEvent) {
	if event.Count <= 0 || ctx == nil {
		return
	}
	logger, _ := ctx.Value(activityLoggerContextKey{}).(activityLogger)
	if logger != nil {
		logger(event)
	}
}
