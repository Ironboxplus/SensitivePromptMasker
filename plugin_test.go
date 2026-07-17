package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func testConfig() config {
	cfg := defaultConfig()
	cfg.Enabled = true
	cfg.Sanitization.Enabled = true
	cfg.Sanitization.ReplacementGroups = []replacementGroup{{
		Models: []string{"gpt-*"}, SourceFormats: []string{"openai"},
		Replacements: []replacement{{Src: "Claude Code", Dst: "CLI", Order: intPointer(1)}, {Src: "CLI", Dst: "client", Order: intPointer(2)}},
	}}
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	return cfg
}

func TestSanitizationMatchesOctopusRoleAndOrderSemantics(t *testing.T) {
	cfg := testConfig()
	body := []byte(`{"messages":[{"role":"system","content":"Claude Code"},{"role":"user","content":"Claude Code"},{"role":"assistant","content":[{"type":"text","text":"Claude Code"}]}]}`)
	out, count, err := sanitizeRequest(body, cfg.Sanitization, "gpt-5", "openai", "")
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("replacement count = %d, want 4 sequential replacements", count)
	}
	var decoded struct {
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Messages[0].Content != "client" || decoded.Messages[1].Content != "Claude Code" {
		t.Fatalf("unexpected sanitized body: %s", out)
	}
}

func TestClaudeAdapterSanitizesSystemAndAssistantOnly(t *testing.T) {
	cfg := testConfig()
	cfg.Sanitization.ReplacementGroups[0].SourceFormats = []string{"claude"}
	body := []byte(`{"system":[{"type":"text","text":"Claude Code"}],"messages":[{"role":"user","content":"Claude Code"},{"role":"assistant","content":[{"type":"text","text":"Claude Code"}]}]}`)
	out, count, err := sanitizeRequest(body, cfg.Sanitization, "gpt-5", "claude", "")
	if err != nil || count != 4 {
		t.Fatalf("Claude adapter count=%d err=%v body=%s", count, err, out)
	}
	if strings.Count(string(out), "client") != 2 || strings.Count(string(out), "Claude Code") != 1 {
		t.Fatalf("Claude adapter rewrote wrong fields: %s", out)
	}
}

func TestCodexAdapterSanitizesInstructionsAndDeveloperInput(t *testing.T) {
	cfg := testConfig()
	cfg.Sanitization.ReplacementGroups[0].SourceFormats = []string{"codex"}
	body := []byte(`{"instructions":"Claude Code","input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"Claude Code"}]},{"type":"message","role":"user","content":[{"type":"input_text","text":"Claude Code"}]}]}`)
	out, count, err := sanitizeRequest(body, cfg.Sanitization, "gpt-5", "codex", "")
	if err != nil || count != 4 {
		t.Fatalf("Codex adapter count=%d err=%v body=%s", count, err, out)
	}
	if strings.Count(string(out), "client") != 2 || strings.Count(string(out), "Claude Code") != 1 {
		t.Fatalf("Codex adapter rewrote wrong fields: %s", out)
	}
}

func TestSanitizationToFormatRunsAfterAuthOnly(t *testing.T) {
	cfg := testConfig()
	cfg.Sanitization.ReplacementGroups[0].SourceFormats = nil
	cfg.Sanitization.ReplacementGroups[0].ToFormats = []string{"codex"}
	body := []byte(`{"instructions":"Claude Code"}`)
	before, count, err := sanitizeRequest(body, cfg.Sanitization, "gpt-5", "openai", "")
	if err != nil || count != 0 || string(before) != string(body) {
		t.Fatalf("before-auth to_formats rule unexpectedly ran: count=%d body=%s err=%v", count, before, err)
	}
	after, count, err := sanitizeRequestAfterAuth(body, cfg.Sanitization, "gpt-5", "openai", "codex")
	if err != nil || count != 2 || !strings.Contains(string(after), "client") {
		t.Fatalf("after-auth to_formats rule did not run: count=%d body=%s err=%v", count, after, err)
	}
}

func TestSanitizationToFormatUsesSourceBodyShapeAfterAuth(t *testing.T) {
	cfg := testConfig()
	cfg.Sanitization.ReplacementGroups[0].SourceFormats = []string{"codex"}
	cfg.Sanitization.ReplacementGroups[0].ToFormats = []string{"claude"}
	body := []byte(`{"instructions":"Claude Code","input":[{"type":"message","role":"developer","content":[{"type":"input_text","text":"Claude Code"}]}]}`)

	after, count, err := sanitizeRequestAfterAuth(body, cfg.Sanitization, "gpt-5", "codex", "claude")
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 || strings.Count(string(after), "client") != 2 {
		t.Fatalf("after-auth request was not sanitized using the source body shape: count=%d body=%s", count, after)
	}
}

func TestConfigNormalizesLegacyFlatReplacementAndPIITypes(t *testing.T) {
	raw := []byte(`enabled: true
sanitization:
  enabled: true
  system_prompt_replacements:
    - models: ["gpt-*"]
      src: old
      dst: new
privacy_shield:
  enabled: true
  debug_cache_ttl_seconds: 123
  pii_types:
    gitleaks: false
    email: false
  pii_aggressive_types:
    loose_secret: true
`)
	cfg, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sanitization.ReplacementGroups) != 1 || cfg.Sanitization.ReplacementGroups[0].Replacements[0].Src != "old" {
		t.Fatalf("legacy replacement was not normalized: %#v", cfg.Sanitization)
	}
	if boolValue(cfg.Privacy.Gitleaks) || boolValue(cfg.Privacy.PII.Email) {
		t.Fatalf("legacy pii_types was not honored: %#v", cfg.Privacy)
	}
	if cfg.Session.TTLSeconds != 123 || !boolValue(cfg.Privacy.PIIAggressiveTypes.LooseSecret) {
		t.Fatalf("legacy privacy TTL/aggressive types were not honored: %#v", cfg)
	}
}

func TestPrivacyShieldRestoresJSONEscaping(t *testing.T) {
	cfg := testConfig()
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	original := `person@example.com and C:\Users\alice\secret`
	body, _ := json.Marshal(map[string]string{"prompt": original})
	session, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.Mappings) < 2 || !strings.Contains(string(redacted), markerPrefix) {
		t.Fatalf("redaction failed: %s", redacted)
	}
	response, _ := json.Marshal(map[string]string{"answer": string(redacted)})
	restored, count := restoreJSONBytes(response, session)
	if count == 0 {
		t.Fatal("no marker restored")
	}
	var decoded map[string]string
	if err := json.Unmarshal(restored, &decoded); err != nil {
		t.Fatalf("invalid restored JSON: %v\n%s", err, restored)
	}
}

func TestPrivacyShieldProducesStablePromptBytesAcrossRetries(t *testing.T) {
	cfg := testConfig()
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"system":[{"type":"text","text":"person@example.com"}],"messages":[{"role":"user","content":"C:\\Users\\alice\\secret"}]}`)

	_, first, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("identical retries produced different prompt bytes:\nfirst=%s\nsecond=%s", first, second)
	}
}

func TestPrivacyMarkerIsStableAcrossProcesses(t *testing.T) {
	run := func() string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPrivacyMarkerSubprocessHelper$")
		cmd.Env = append(os.Environ(), "CPA_MARKER_SUBPROCESS=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("marker subprocess failed: %v\n%s", err, output)
		}
		return markerFromBody(t, output)
	}
	first := run()
	second := run()
	if first != second {
		t.Fatalf("same JSON location changed marker across processes: first=%q second=%q", first, second)
	}
}

func TestPrivacyMarkerSubprocessHelper(t *testing.T) {
	if os.Getenv("CPA_MARKER_SUBPROCESS") != "1" {
		t.Skip("subprocess helper")
	}
	fmt.Print(newPrivacySession().newMarker("/system/0/text\x00pii-email\x000"))
}

func TestPrivacyMarkerSeparatesDifferentSecretsAtSameLocation(t *testing.T) {
	cfg := testConfig()
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	_, first, err := redactJSON(context.Background(), []byte(`{"system":[{"type":"text","text":"first@example.com"}]}`), cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := redactJSON(context.Background(), []byte(`{"system":[{"type":"text","text":"second@example.com"}]}`), cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	if markerFromBody(t, first) == markerFromBody(t, second) {
		t.Fatalf("different secrets at the same JSON location share a marker: first=%s second=%s", first, second)
	}
}

func TestPrivacyShieldPreservesUntouchedJSONBytes(t *testing.T) {
	cfg := testConfig()
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("{\n  \"z\": 1, \"messages\": [ { \"content\": \"person@example.com\", \"role\": \"user\" } ],\n  \"a\": {\"escaped\":\"keep\\\\path\"}\n}")
	_, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	marker := markerFromBody(t, redacted)
	roundTrip := bytes.ReplaceAll(redacted, []byte(marker), []byte("person@example.com"))
	if !bytes.Equal(roundTrip, body) {
		t.Fatalf("redaction rewrote untouched JSON bytes:\noriginal=%s\nredacted=%s", body, redacted)
	}
}

func TestPrivacyShieldFallsBackForDuplicateJSONKeys(t *testing.T) {
	cfg := testConfig()
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"metadata":{"label":"first","label":"second"},"messages":[{"role":"user","content":"person@example.com"}]}`)
	_, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatalf("valid JSON with duplicate keys should retain the previous fallback behavior: %v", err)
	}
	if bytes.Contains(redacted, []byte("person@example.com")) || !bytes.Contains(redacted, []byte(markerPrefix)) {
		t.Fatalf("fallback redaction failed: %s", redacted)
	}
}

func TestGenericTokenDetectorIgnoresMCPToolIdentifiers(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	cfg.Privacy.PII.GenericToken = boolPointer(true)
	cfg.Privacy.PIIAggressiveTypes.GenericToken = boolPointer(true)
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"messages":[{"role":"user","content":"mcp__plugin_oh-my-claudecode_t__project_memory_write oh-my-claudecode-project-session-manager AbCDef0123456789_zyXWVUTsrqponmlk"}]}`)
	_, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(redacted, []byte("mcp__plugin_oh-my-claudecode_t__project_memory_write")) {
		t.Fatalf("public MCP tool identifier was redacted: %s", redacted)
	}
	if !bytes.Contains(redacted, []byte("oh-my-claudecode-project-session-manager")) {
		t.Fatalf("word-like public identifier was redacted: %s", redacted)
	}
	if bytes.Contains(redacted, []byte("AbCDef0123456789_zyXWVUTsrqponmlk")) || !bytes.Contains(redacted, []byte(markerPrefix)) {
		t.Fatalf("real high-entropy token was not redacted: %s", redacted)
	}
}

func TestGenericTokenDetectorIgnoresPublicMixedCaseIdentifiers(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	cfg.Privacy.PII.GenericToken = boolPointer(true)
	cfg.Privacy.PIIAggressiveTypes.GenericToken = boolPointer(true)
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	const (
		publicIdentifier = "SensitivePromptMaskerRequestInterceptor"
		realToken        = "AbCDef0123456789_zyXWVUTsrqponmlk"
	)
	body := []byte(`{"tools":[{"description":"` + publicIdentifier + `"}],"messages":[{"role":"user","content":"` + realToken + `"}]}`)
	session, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(redacted, []byte(publicIdentifier)) {
		t.Fatalf("public mixed-case identifier was redacted: %s", redacted)
	}
	if bytes.Contains(redacted, []byte(realToken)) || !bytes.Contains(redacted, []byte(markerPrefix)) {
		t.Fatalf("real high-entropy token was not redacted: %s", redacted)
	}
	if len(session.Mappings) != 1 {
		t.Fatalf("mapping count = %d, want only the real token; mappings=%#v", len(session.Mappings), session.Mappings)
	}
}

func TestPhoneDetectorIgnoresTechnicalNumbersButKeepsPhones(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	cfg.Privacy.PII.Phone = boolPointer(true)
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	const (
		decimalMetric = "1234.56789"
		versionNumber = "2026-12345"
		localBuildID  = "1234567"
		dottedCounter = "123.456.789.01"
		openTuple     = "(1234.56789"
		usPhone       = "+1 (415) 555-2671"
		cnPhone       = "13812345678"
	)
	body := []byte(`{"messages":[{"role":"user","content":"metric ` + decimalMetric + ` version ` + versionNumber + ` build ` + localBuildID + ` counter ` + dottedCounter + ` tuple ` + openTuple + ` phones ` + usPhone + ` and ` + cnPhone + `"}]}`)
	session, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	for _, technical := range []string{decimalMetric, versionNumber, localBuildID, dottedCounter, openTuple} {
		if !bytes.Contains(redacted, []byte(technical)) {
			t.Fatalf("technical number %q was redacted: %s", technical, redacted)
		}
	}
	for _, phone := range []string{usPhone, cnPhone} {
		if bytes.Contains(redacted, []byte(phone)) {
			t.Fatalf("phone %q was not redacted: %s", phone, redacted)
		}
	}
	if len(session.Mappings) != 2 {
		t.Fatalf("mapping count = %d, want two real phones; mappings=%#v", len(session.Mappings), session.Mappings)
	}
}

func TestPhoneDetectorIgnoresCalendarDates(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	cfg.Privacy.PII.Phone = boolPointer(true)
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"messages":[{"role":"user","content":"dates 2026-07-16 and 20260716; phone +1 415 555 2671"}]}`)
	_, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(redacted, []byte("2026-07-16")) || !bytes.Contains(redacted, []byte("20260716")) {
		t.Fatalf("calendar date was redacted as a phone number: %s", redacted)
	}
	if bytes.Contains(redacted, []byte("+1 415 555 2671")) || !bytes.Contains(redacted, []byte(markerPrefix)) {
		t.Fatalf("real phone number was not redacted: %s", redacted)
	}
}

func TestStreamRestorerCarriesSplitMarker(t *testing.T) {
	session := newPrivacySession()
	marker := session.newMarker("test")
	session.Mappings = []mapping{{Marker: marker, Original: `secret\"value`}}
	restorer := &streamRestorer{session: session}
	first, drop, _ := restorer.feed([]byte(`data: {"delta":"` + marker[:12]))
	if drop || len(first) == 0 {
		t.Fatalf("first chunk should emit safe prefix: drop=%v body=%q", drop, first)
	}
	second, _, count := restorer.feed([]byte(marker[12:] + `"}\n\n`))
	if count != 1 || !strings.Contains(string(second), `secret\\\"value`) {
		t.Fatalf("split restore failed: %q", second)
	}
}

func TestStreamRestorerDoesNotTreatNullFinishReasonAsTerminal(t *testing.T) {
	session := newPrivacySession()
	marker := session.newMarker("test")
	session.Mappings = []mapping{{Marker: marker, Original: "secret"}}
	restorer := &streamRestorer{session: session}
	first, _, _ := restorer.feed([]byte(`data: {"finish_reason":null,"delta":"` + marker[:15]))
	if strings.Contains(string(first), marker[:15]) {
		t.Fatalf("partial marker leaked from non-terminal chunk: %q", first)
	}
	second, _, count := restorer.feed([]byte(marker[15:] + `"}\n\n`))
	if count != 1 || !strings.Contains(string(second), "secret") {
		t.Fatalf("marker was not restored after null finish_reason: %q", second)
	}
}

func TestContentStreamRestorerDoesNotBufferNonMarkerCPAText(t *testing.T) {
	session := newPrivacySession()
	marker := session.newMarker("test")
	session.Mappings = []mapping{{Marker: marker, Original: "secret"}}
	restorer := newContentStreamRestorer(session)

	out, count := restorer.feed("text", "ordinary CPA_X")
	if count != 0 || out != "ordinary CPA_X" {
		t.Fatalf("ordinary CPA text was buffered as a marker prefix: count=%d body=%q", count, out)
	}
}

func TestContentStreamRestorerDoesNotSplitCompleteMarkerEndingInPrefix(t *testing.T) {
	for _, tail := range []byte{'C', 'P', 'A', 'S'} {
		t.Run(string(tail), func(t *testing.T) {
			session := newPrivacySession()
			marker := markerPrefix + "AAAAAAAABBBB" + string(tail)
			session.addMapping(mapping{Marker: marker, Original: "restored-" + string(tail)})
			restorer := newContentStreamRestorer(session)

			if safe := partialMarkerStart([]byte(marker), session); safe != len(marker) {
				t.Fatalf("complete marker ending in %q was retained as a prefix: safe=%d marker=%q", tail, safe, marker)
			}
			out, count := restorer.feed("text", marker)
			if count != 1 || out != "restored-"+string(tail) {
				t.Fatalf("complete marker ending in %q was not restored: count=%d out=%q", tail, count, out)
			}
			if len(restorer.buffers) != 0 {
				t.Fatalf("complete marker ending in %q left an unread carry buffer: %#v", tail, restorer.buffers)
			}
		})
	}
}

func TestKnownProtocolFieldsRestoreCompleteMarkerEndingInPrefix(t *testing.T) {
	tests := []struct {
		name   string
		format string
		chunk  func(string) []byte
	}{
		{
			name: "Claude partial JSON", format: "claude",
			chunk: func(value string) []byte {
				event, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": value}})
				return append(append([]byte("event: content_block_delta\ndata: "), event...), []byte("\n\n")...)
			},
		},
		{
			name: "OpenAI Chat arguments", format: "openai",
			chunk: func(value string) []byte {
				event, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": 0, "function": map[string]any{"arguments": value}}}}, "finish_reason": nil}}})
				return append(append([]byte("data: "), event...), []byte("\n\n")...)
			},
		},
		{
			name: "Codex Responses arguments", format: "openai-response",
			chunk: func(value string) []byte {
				event, _ := json.Marshal(map[string]any{"type": "response.function_call_arguments.delta", "item_id": "call-1", "output_index": 0, "delta": value})
				return append(append([]byte("data: "), event...), []byte("\n\n")...)
			},
		},
	}

	for _, test := range tests {
		for _, tail := range []byte{'C', 'P', 'A', 'S'} {
			t.Run(test.name+"/"+string(tail), func(t *testing.T) {
				session := newPrivacySession()
				marker := markerPrefix + "AAAAAAAABBBB" + string(tail)
				session.addMapping(mapping{Marker: marker, Original: "private-project/ann0.json"})
				restorer := &streamRestorer{session: session, adapter: adapterForFormat(test.format)}

				output, drop, count := restorer.feed(test.chunk(marker))
				if drop || count != 1 || bytes.Contains(output, []byte(marker)) || !bytes.Contains(output, []byte("private-project/ann0.json")) {
					t.Fatalf("complete marker ending in %q leaked from %s: drop=%v count=%d body=%s", tail, test.name, drop, count, output)
				}
			})
		}
	}
}

func TestStreamRestorerRestoresMarkerSplitAcrossProtocolContentDeltas(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		firstChunk  func(string) []byte
		secondChunk func(string) []byte
	}{
		{
			name:   "OpenAI chat content",
			format: "openai",
			firstChunk: func(text string) []byte {
				return []byte(`data: {"choices":[{"index":0,"delta":{"content":"` + text + `"},"finish_reason":null}]}` + "\n\n")
			},
			secondChunk: func(text string) []byte {
				return []byte(`data: {"choices":[{"index":0,"delta":{"content":"` + text + `"},"finish_reason":null}]}` + "\n\n")
			},
		},
		{
			name:   "Claude text delta",
			format: "claude",
			firstChunk: func(text string) []byte {
				return []byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + text + `"}}` + "\n\n")
			},
			secondChunk: func(text string) []byte {
				return []byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + text + `"}}` + "\n\n")
			},
		},
		{
			name:   "Codex Responses delta",
			format: "codex",
			firstChunk: func(text string) []byte {
				return []byte(`data: {"type":"response.output_text.delta","item_id":"item-1","output_index":0,"content_index":0,"delta":"` + text + `"}` + "\n\n")
			},
			secondChunk: func(text string) []byte {
				return []byte(`data: {"type":"response.output_text.delta","item_id":"item-1","output_index":0,"content_index":0,"delta":"` + text + `"}` + "\n\n")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newPrivacySession()
			marker := session.newMarker("test")
			session.Mappings = []mapping{{Marker: marker, Original: "person@example.com"}}
			restorer := &streamRestorer{session: session, adapter: adapterForFormat(test.format)}

			first, firstDrop, firstCount := restorer.feed(test.firstChunk(marker[:14]))
			if firstCount != 0 {
				t.Fatalf("first content delta restored a complete marker: count=%d body=%q", firstCount, first)
			}
			if !firstDrop && strings.Contains(string(first), marker[:14]) {
				t.Fatalf("partial marker leaked in the first valid SSE event: %q", first)
			}

			second, secondDrop, secondCount := restorer.feed(test.secondChunk(marker[14:]))
			if secondDrop || secondCount != 1 || !strings.Contains(string(second), "person@example.com") {
				t.Fatalf("split content-delta marker was not restored: drop=%v count=%d body=%q", secondDrop, secondCount, second)
			}
			if strings.Contains(string(second), marker) {
				t.Fatalf("marker leaked after content-delta restoration: %q", second)
			}
		})
	}
}

func TestStreamRestorerRestoresMarkerSplitAcrossToolArgumentDeltas(t *testing.T) {
	tests := []struct {
		name   string
		format string
		chunk  func(string) []byte
	}{
		{
			name:   "OpenAI tool arguments",
			format: "openai",
			chunk: func(text string) []byte {
				return []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"` + text + `"}}]},"finish_reason":null}]}` + "\n\n")
			},
		},
		{
			name:   "Claude partial JSON",
			format: "claude",
			chunk: func(text string) []byte {
				return []byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"` + text + `"}}` + "\n\n")
			},
		},
		{
			name:   "Codex function arguments",
			format: "codex",
			chunk: func(text string) []byte {
				return []byte(`data: {"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":0,"delta":"` + text + `"}` + "\n\n")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newPrivacySession()
			marker := session.newMarker("tool")
			session.Mappings = []mapping{{Marker: marker, Original: "person@example.com"}}
			restorer := &streamRestorer{session: session, adapter: adapterForFormat(test.format)}

			split := len(marker) / 2
			first, _, _ := restorer.feed(test.chunk(marker[:split]))
			if strings.Contains(string(first), marker[:split]) {
				t.Fatalf("partial marker leaked in tool delta: %q", first)
			}
			second, drop, count := restorer.feed(test.chunk(marker[split:]))
			if drop || count != 1 || !strings.Contains(string(second), "person@example.com") {
				t.Fatalf("tool delta was not restored: drop=%v count=%d body=%q", drop, count, second)
			}
		})
	}
}

func TestStreamRestorerEscapesWindowsPathInsideToolArgumentJSON(t *testing.T) {
	type toolProtocol struct {
		name    string
		format  string
		chunk   func(string) []byte
		extract func([]byte) string
	}
	jsonString := func(value string) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	decodeEvent := func(chunk []byte) map[string]any {
		line := chunk
		if index := bytes.Index(line, []byte("data:")); index >= 0 {
			line = line[index+len("data:"):]
		}
		line = bytes.TrimSpace(line)
		var event map[string]any
		if len(line) == 0 {
			return event
		}
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("decode restored event: %v\n%s", err, line)
		}
		return event
	}
	protocols := []toolProtocol{
		{
			name: "OpenAI tool arguments", format: "openai",
			chunk: func(text string) []byte {
				return []byte(`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":` + jsonString(text) + `}}]} ,"finish_reason":null}]}` + "\n\n")
			},
			extract: func(chunk []byte) string {
				event := decodeEvent(chunk)
				if len(event) == 0 {
					return ""
				}
				return event["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)["arguments"].(string)
			},
		},
		{
			name: "Claude partial JSON", format: "claude",
			chunk: func(text string) []byte {
				return []byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":` + jsonString(text) + `}}` + "\n\n")
			},
			extract: func(chunk []byte) string {
				event := decodeEvent(chunk)
				if len(event) == 0 {
					return ""
				}
				return event["delta"].(map[string]any)["partial_json"].(string)
			},
		},
		{
			name: "Codex function arguments", format: "codex",
			chunk: func(text string) []byte {
				return []byte(`data: {"type":"response.function_call_arguments.delta","item_id":"call-1","output_index":0,"delta":` + jsonString(text) + `}` + "\n\n")
			},
			extract: func(chunk []byte) string {
				event := decodeEvent(chunk)
				if len(event) == 0 {
					return ""
				}
				return event["delta"].(string)
			},
		},
	}

	const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
	for _, protocol := range protocols {
		for split := 1; split < len(newPrivacySession().newMarker("windows-path")); split++ {
			t.Run(fmt.Sprintf("%s/split-%d", protocol.name, split), func(t *testing.T) {
				session := newPrivacySession()
				marker := session.newMarker("windows-path")
				session.Mappings = []mapping{{Marker: marker, Original: windowsPath}}
				restorer := &streamRestorer{session: session, adapter: adapterForFormat(protocol.format)}
				innerPrefix := `{"command":"git fetch origin","description":"Fetch latest from remote","working_directory":"`
				innerSuffix := `"}`
				first, _, _ := restorer.feed(protocol.chunk(innerPrefix + marker[:split]))
				second, drop, count := restorer.feed(protocol.chunk(marker[split:] + innerSuffix))
				if drop || count != 1 {
					t.Fatalf("restoration failed: drop=%v count=%d first=%q second=%q", drop, count, first, second)
				}
				innerJSON := protocol.extract(first) + protocol.extract(second)
				var arguments map[string]any
				if err := json.Unmarshal([]byte(innerJSON), &arguments); err != nil {
					t.Fatalf("restored tool arguments are invalid JSON: %v\n%s", err, innerJSON)
				}
				if arguments["working_directory"] != windowsPath {
					t.Fatalf("working_directory = %q, want %q", arguments["working_directory"], windowsPath)
				}
			})
		}
	}
}

func TestStreamRestorerLeavesClaudeSignedThinkingMarkersUntouched(t *testing.T) {
	session := newPrivacySession()
	marker := session.newMarker("signed-thinking")
	session.Mappings = []mapping{{Marker: marker, Original: "person@example.com"}}
	restorer := &streamRestorer{session: session, adapter: adapterForFormat("claude")}

	thinking := []byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"` + marker + `"}}` + "\n\n")
	restoredThinking, drop, count := restorer.feed(thinking)
	if !drop || count != 0 || len(restoredThinking) != 0 {
		t.Fatalf("signed thinking was not buffered: drop=%v count=%d body=%s", drop, count, restoredThinking)
	}

	signature := []byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"signature-for-marker-text"}}` + "\n\n")
	restoredSignature, drop, count := restorer.feed(signature)
	if drop || count != 0 || !bytes.Contains(restoredSignature, []byte(marker)) || bytes.Contains(restoredSignature, []byte("person@example.com")) ||
		!bytes.Contains(restoredSignature, []byte(`"signature":"signature-for-marker-text"`)) {
		t.Fatalf("signature delta changed: drop=%v count=%d body=%s", drop, count, restoredSignature)
	}
}

func TestStreamRestorerRestoresUnsignedClaudeThinkingAtBlockStop(t *testing.T) {
	session := newPrivacySession()
	marker := session.newMarker("unsigned-thinking")
	session.Mappings = []mapping{{Marker: marker, Original: "person@example.com"}}
	restorer := &streamRestorer{session: session, adapter: adapterForFormat("claude")}

	chunks := [][]byte{
		[]byte(`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}` + "\n\n"),
		[]byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"email ` + marker + `"}}` + "\n\n"),
		[]byte(`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n"),
	}
	var output []byte
	total := 0
	for _, chunk := range chunks {
		body, _, count := restorer.feed(chunk)
		output = append(output, body...)
		total += count
	}
	if total != 1 || !bytes.Contains(output, []byte("email person@example.com")) || bytes.Contains(output, []byte(marker)) {
		t.Fatalf("unsigned thinking was not restored at block stop: count=%d body=%s", total, output)
	}
}

func TestStreamRestorerKeepsSignedClaudeThinkingBufferedTextMasked(t *testing.T) {
	session := newPrivacySession()
	marker := session.newMarker("signed-thinking-sequence")
	session.Mappings = []mapping{{Marker: marker, Original: "person@example.com"}}
	restorer := &streamRestorer{session: session, adapter: adapterForFormat("claude")}

	chunks := [][]byte{
		[]byte(`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}` + "\n\n"),
		[]byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"email ` + marker + `"}}` + "\n\n"),
		[]byte(`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"signature-for-marker-text"}}` + "\n\n"),
		[]byte(`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n"),
	}
	var output []byte
	total := 0
	for _, chunk := range chunks {
		body, _, count := restorer.feed(chunk)
		output = append(output, body...)
		total += count
	}
	if total != 0 || !bytes.Contains(output, []byte(marker)) || bytes.Contains(output, []byte("person@example.com")) || !bytes.Contains(output, []byte("signature-for-marker-text")) {
		t.Fatalf("signed thinking was not kept atomically masked: count=%d body=%s", total, output)
	}
}

func TestCodexCustomToolInputDeltaRestoresPlainText(t *testing.T) {
	const windowsPath = `E:\repo\a.txt`
	session := newPrivacySession()
	marker := session.newMarker("custom-tool-path")
	session.Mappings = []mapping{{Marker: marker, Original: windowsPath}}
	restorer := &streamRestorer{session: session, adapter: adapterForFormat("codex")}

	chunk := []byte(`data: {"type":"response.custom_tool_call_input.delta","item_id":"ctc_1","call_id":"call_1","delta":"*** Update File: ` + marker + `"}` + "\n\n")
	restored, drop, count := restorer.feed(chunk)
	if drop || count != 1 {
		t.Fatalf("custom-tool restoration failed: drop=%v count=%d body=%s", drop, count, restored)
	}
	line := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(restored), []byte("data:")))
	var event map[string]any
	if err := json.Unmarshal(line, &event); err != nil {
		t.Fatalf("restored custom-tool event is invalid JSON: %v\n%s", err, line)
	}
	if got := event["delta"]; got != "*** Update File: "+windowsPath {
		t.Fatalf("custom-tool delta = %q, want raw text %q", got, "*** Update File: "+windowsPath)
	}
}

func TestCodexCompleteFunctionCallEventsRestoreArgumentsJSON(t *testing.T) {
	const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
	tests := []struct {
		name    string
		chunk   func(string) []byte
		extract func(map[string]any) string
	}{
		{
			name: "arguments done",
			chunk: func(arguments string) []byte {
				encoded, _ := json.Marshal(arguments)
				return []byte(`data: {"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":` + string(encoded) + `}` + "\n\n")
			},
			extract: func(event map[string]any) string { return event["arguments"].(string) },
		},
		{
			name: "output item done",
			chunk: func(arguments string) []byte {
				encoded, _ := json.Marshal(arguments)
				return []byte(`data: {"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"exec_command","arguments":` + string(encoded) + `}}` + "\n\n")
			},
			extract: func(event map[string]any) string { return event["item"].(map[string]any)["arguments"].(string) },
		},
		{
			name: "response completed",
			chunk: func(arguments string) []byte {
				encoded, _ := json.Marshal(arguments)
				return []byte(`data: {"type":"response.completed","response":{"id":"resp_1","status":"completed","output":[{"type":"function_call","call_id":"call_1","name":"exec_command","arguments":` + string(encoded) + `}]}}` + "\n\n")
			},
			extract: func(event map[string]any) string {
				return event["response"].(map[string]any)["output"].([]any)[0].(map[string]any)["arguments"].(string)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newPrivacySession()
			marker := session.newMarker("complete-function-call")
			session.Mappings = []mapping{{Marker: marker, Original: windowsPath}}
			restorer := &streamRestorer{session: session, adapter: adapterForFormat("codex")}
			arguments := `{"working_directory":"` + marker + `"}`
			restored, drop, count := restorer.feed(test.chunk(arguments))
			if drop || count != 1 {
				t.Fatalf("complete event restoration failed: drop=%v count=%d body=%s", drop, count, restored)
			}
			line := bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(restored), []byte("data:")))
			var event map[string]any
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatalf("restored event is invalid JSON: %v\n%s", err, line)
			}
			innerJSON := test.extract(event)
			var inner map[string]any
			if err := json.Unmarshal([]byte(innerJSON), &inner); err != nil {
				t.Fatalf("restored arguments are invalid JSON: %v\n%s", err, innerJSON)
			}
			if inner["working_directory"] != windowsPath {
				t.Fatalf("working_directory = %q, want %q", inner["working_directory"], windowsPath)
			}
		})
	}
}

func TestStreamRestorerAutoDetectsRawClaudeDeltaBehindOpenAIFormat(t *testing.T) {
	session := newPrivacySession()
	marker := session.newMarker("translated-stream")
	session.Mappings = []mapping{{Marker: marker, Original: "CPA_E2E_SECRET_REAL_STREAM"}}
	// CPA can expose the original client format while the intercepted chunk is
	// still a provider-native JSON event. The stream shape must be detected from
	// the event itself instead of trusting only SourceFormat.
	restorer := &streamRestorer{session: session, adapter: adapterForFormat("openai")}

	first, _, _ := restorer.feed([]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + marker[:1] + `"}}`))
	if strings.Contains(string(first), marker[:1]) {
		t.Fatalf("one-byte marker prefix leaked from raw Claude delta: %q", first)
	}
	second, drop, count := restorer.feed([]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + marker[1:] + `"}}`))
	if drop || count != 1 || !strings.Contains(string(second), "CPA_E2E_SECRET_REAL_STREAM") {
		t.Fatalf("raw translated stream marker was not restored: drop=%v count=%d body=%q", drop, count, second)
	}
}

func TestClaudeAndCodexStreamAdaptersRecognizeTheirTerminalEvents(t *testing.T) {
	if !adapterForFormat("claude").StreamTerminal([]byte(`data: {"type":"message_stop"}`)) {
		t.Fatal("Claude message_stop was not recognized")
	}
	if adapterForFormat("claude").StreamTerminal([]byte(`data: {"type":"content_block_delta"}`)) {
		t.Fatal("Claude content delta was treated as terminal")
	}
	if !adapterForFormat("codex").StreamTerminal([]byte(`data: {"type":"response.completed"}`)) {
		t.Fatal("Codex response.completed was not recognized")
	}
	if adapterForFormat("codex").StreamTerminal([]byte(`data: {"type":"response.output_text.delta"}`)) {
		t.Fatal("Codex output delta was treated as terminal")
	}
}

func TestEngineUsesCPARequestIDForIsolation(t *testing.T) {
	cfg := testConfig()
	instance, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := requestInterceptRequest{Model: "gpt-5", Body: []byte(`{"prompt":"person@example.com"}`), Metadata: map[string]any{cpaRequestIDMetadataKey: "req-1"}}
	redacted, err := instance.interceptAfter(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	response := instance.interceptResponse(responseInterceptRequest{Model: "gpt-5", RequestBody: redacted.Body, Body: []byte(`{"answer":"` + markerFromBody(t, redacted.Body) + `"}`), Metadata: req.Metadata})
	if !strings.Contains(string(response.Body), "person@example.com") {
		t.Fatalf("response not restored: %s", response.Body)
	}
}

func TestEngineUsesExistingRequestIDsAcrossRewrittenBodies(t *testing.T) {
	type protocolCase struct {
		name    string
		format  string
		event   func(string) map[string]any
		extract func(map[string]any) string
	}
	protocols := []protocolCase{
		{
			name: "Claude partial JSON", format: "claude",
			event: func(text string) map[string]any {
				return map[string]any{
					"type": "content_block_delta", "index": 0,
					"delta": map[string]any{"type": "input_json_delta", "partial_json": text},
				}
			},
			extract: func(event map[string]any) string {
				return event["delta"].(map[string]any)["partial_json"].(string)
			},
		},
		{
			name: "Codex Responses function arguments", format: "openai-response",
			event: func(text string) map[string]any {
				return map[string]any{
					"type": "response.function_call_arguments.delta", "item_id": "call-1",
					"output_index": 0, "delta": text,
				}
			},
			extract: func(event map[string]any) string { return event["delta"].(string) },
		},
		{
			name: "OpenAI Chat tool arguments", format: "openai",
			event: func(text string) map[string]any {
				return map[string]any{
					"choices": []any{map[string]any{
						"index": 0, "finish_reason": nil,
						"delta": map[string]any{"tool_calls": []any{map[string]any{
							"index": 0, "function": map[string]any{"arguments": text},
						}}},
					}},
				}
			},
			extract: func(event map[string]any) string {
				return event["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)["arguments"].(string)
			},
		},
	}

	for _, protocol := range protocols {
		for _, sse := range []bool{false, true} {
			mode := "raw JSON"
			if sse {
				mode = "SSE"
			}
			t.Run(protocol.name+"/"+mode, func(t *testing.T) {
				instance, err := newEngine(testConfig())
				if err != nil {
					t.Fatal(err)
				}
				requestHeaders := http.Header{"X-Client-Request-Id": []string{"request-" + protocol.format}}
				const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
				requestBody, err := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": "work in " + windowsPath}}})
				if err != nil {
					t.Fatal(err)
				}
				redacted, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
					SourceFormat: protocol.format, ToFormat: protocol.format, Model: "test-model", Body: requestBody, Headers: requestHeaders,
				})
				if err != nil {
					t.Fatal(err)
				}
				if redacted.Headers.Get("X-Client-Request-Id") != requestHeaders.Get("X-Client-Request-Id") {
					t.Fatalf("existing request ID changed: before=%v after=%v", requestHeaders, redacted.Headers)
				}
				marker := markerFromBody(t, redacted.Body)
				changedOriginal := []byte(`{"body_changed_after_interception":true}`)
				changedRequest := []byte(`{"provider_translated_body":true}`)
				instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
					SourceFormat: protocol.format, Model: "test-model", OriginalRequest: changedOriginal,
					RequestBody: changedRequest, RequestHeaders: redacted.Headers, ChunkIndex: -1,
				})

				arguments, err := json.Marshal(map[string]string{"working_directory": marker})
				if err != nil {
					t.Fatal(err)
				}
				split := bytes.Index(arguments, []byte(marker)) + len(marker)/2
				makeChunk := func(text string) []byte {
					encoded, marshalErr := json.Marshal(protocol.event(text))
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					if !sse {
						return encoded
					}
					return append(append([]byte("data: "), encoded...), []byte("\n\n")...)
				}
				first := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
					SourceFormat: protocol.format, Model: "test-model", OriginalRequest: changedOriginal,
					RequestBody: changedRequest, RequestHeaders: redacted.Headers, Body: makeChunk(string(arguments[:split])), ChunkIndex: 0,
				})
				second := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
					SourceFormat: protocol.format, Model: "test-model", OriginalRequest: changedOriginal,
					RequestBody: changedRequest, RequestHeaders: redacted.Headers, Body: makeChunk(string(arguments[split:])), ChunkIndex: 1,
				})
				if first.DropChunk || second.DropChunk {
					t.Fatalf("request-scoped restoration dropped a tool delta: first=%v second=%v", first.DropChunk, second.DropChunk)
				}
				firstEvent, ok := decodeStreamFrameEvent(first.Body)
				if !ok {
					t.Fatalf("first restored event is invalid %s: %s", mode, first.Body)
				}
				secondEvent, ok := decodeStreamFrameEvent(second.Body)
				if !ok {
					t.Fatalf("second restored event is invalid %s: %s", mode, second.Body)
				}
				joined := protocol.extract(firstEvent) + protocol.extract(secondEvent)
				if strings.Contains(joined, marker) || strings.Contains(joined, marker[:len(marker)/2]) {
					t.Fatalf("privacy marker leaked into tool arguments: %s", joined)
				}
				var restoredArguments map[string]string
				if err := json.Unmarshal([]byte(joined), &restoredArguments); err != nil {
					t.Fatalf("restored tool arguments are invalid JSON: %v\n%s", err, joined)
				}
				if restoredArguments["working_directory"] != windowsPath {
					t.Fatalf("working_directory = %q, want %q", restoredArguments["working_directory"], windowsPath)
				}
			})
		}
	}
}

func TestEngineRequestIDIsolationForIdenticalConcurrentStreams(t *testing.T) {
	instance, err := newEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	type activeRequest struct {
		headers  http.Header
		original string
		marker   string
		parts    [2]string
	}
	start := func(id, original string) activeRequest {
		headers := http.Header{"X-Client-Request-Id": []string{"concurrent-" + id}}
		requestBody, marshalErr := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": original}}})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		redacted, interceptErr := instance.interceptAfter(context.Background(), requestInterceptRequest{
			SourceFormat: "claude", ToFormat: "claude", Model: "test-model", Body: requestBody, Headers: headers,
		})
		if interceptErr != nil {
			t.Fatal(interceptErr)
		}
		marker := markerFromBody(t, redacted.Body)
		arguments, marshalErr := json.Marshal(map[string]string{"value": marker})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		split := bytes.Index(arguments, []byte(marker)) + len(marker)/2
		instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
			SourceFormat: "claude", Model: "test-model", OriginalRequest: []byte(`{"same":true}`),
			RequestBody: []byte(`{"same":true}`), RequestHeaders: redacted.Headers, ChunkIndex: -1,
		})
		return activeRequest{headers: redacted.Headers, original: original, marker: marker, parts: [2]string{string(arguments[:split]), string(arguments[split:])}}
	}
	makeChunk := func(text string) []byte {
		body, marshalErr := json.Marshal(map[string]any{
			"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": text},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return body
	}
	feed := func(request activeRequest, part, index int) string {
		response := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
			SourceFormat: "claude", Model: "test-model", OriginalRequest: []byte(`{"same":true}`),
			RequestBody: []byte(`{"same":true}`), RequestHeaders: request.headers, Body: makeChunk(request.parts[part]), ChunkIndex: index,
		})
		if response.DropChunk {
			t.Fatalf("request %q part %d was dropped", request.original, part)
		}
		event, ok := decodeStreamFrameEvent(response.Body)
		if !ok {
			t.Fatalf("request %q part %d returned invalid JSON: %s", request.original, part, response.Body)
		}
		return event["delta"].(map[string]any)["partial_json"].(string)
	}

	first := start("first", "first.person@example.com")
	second := start("second", "second.person@example.com")
	firstJSON := feed(first, 0, 0)
	secondJSON := feed(second, 0, 0)
	firstJSON += feed(first, 1, 1)
	secondJSON += feed(second, 1, 1)
	for _, result := range []struct {
		request activeRequest
		body    string
	}{{first, firstJSON}, {second, secondJSON}} {
		if strings.Contains(result.body, first.marker) || strings.Contains(result.body, second.marker) {
			t.Fatalf("request %q leaked or received a foreign marker: %s", result.request.original, result.body)
		}
		var arguments map[string]string
		if err := json.Unmarshal([]byte(result.body), &arguments); err != nil {
			t.Fatalf("request %q restored invalid JSON: %v\n%s", result.request.original, err, result.body)
		}
		if arguments["value"] != result.request.original {
			t.Fatalf("request %q restored foreign value %q", result.request.original, arguments["value"])
		}
	}
}

func TestEnginePrefersCPARequestIDOverSharedClientRequestHeader(t *testing.T) {
	cfg := testConfig()
	instance, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sharedHeaders := http.Header{"X-Client-Request-Id": []string{"shared-agent-request"}}

	start := func(requestID, original string) requestInterceptResponse {
		body, marshalErr := json.Marshal(map[string]any{
			"messages": []any{map[string]any{"role": "user", "content": original}},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		response, interceptErr := instance.interceptAfter(context.Background(), requestInterceptRequest{
			SourceFormat: "claude",
			ToFormat:     "claude",
			Model:        "claude-sonnet-5",
			Headers:      sharedHeaders,
			Body:         body,
			Metadata:     map[string]any{cpaRequestIDMetadataKey: requestID},
		})
		if interceptErr != nil {
			t.Fatal(interceptErr)
		}
		return response
	}

	first := start("cpa-agent-1", `C:\private\agent-one\chunk0.json`)
	second := start("cpa-agent-2", `C:\private\agent-two\chunk0.json`)
	firstMarker := markerFromBody(t, first.Body)
	secondMarker := markerFromBody(t, second.Body)
	if firstMarker == secondMarker {
		t.Fatalf("concurrent requests unexpectedly share marker %q", firstMarker)
	}

	response := instance.interceptResponse(responseInterceptRequest{
		SourceFormat:   "claude",
		Model:          "claude-sonnet-5",
		RequestHeaders: sharedHeaders,
		RequestBody:    first.Body,
		Metadata:       map[string]any{cpaRequestIDMetadataKey: "cpa-agent-1"},
		Body:           []byte(`{"content":[{"type":"tool_use","name":"Search","input":{"pattern":"**/` + firstMarker + `*"}}]}`),
	})
	if bytes.Contains(response.Body, []byte(firstMarker)) || !bytes.Contains(response.Body, []byte(`agent-one`)) {
		t.Fatalf("shared client request header selected the wrong privacy session: %s", response.Body)
	}
}

func TestEngineKeepsConcurrentStreamsIsolatedWhenClientRequestHeaderIsShared(t *testing.T) {
	instance, err := newEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	sharedHeaders := http.Header{"X-Client-Request-Id": []string{"shared-agent-request"}}

	type activeRequest struct {
		id       string
		original string
		body     []byte
		marker   string
	}
	start := func(id, original string) activeRequest {
		requestBody, marshalErr := json.Marshal(map[string]any{
			"messages": []any{map[string]any{"role": "user", "content": original}},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		redacted, interceptErr := instance.interceptAfter(context.Background(), requestInterceptRequest{
			SourceFormat: "claude", ToFormat: "claude", Model: "claude-sonnet-5",
			Headers: sharedHeaders, Body: requestBody,
			Metadata: map[string]any{cpaRequestIDMetadataKey: id},
		})
		if interceptErr != nil {
			t.Fatal(interceptErr)
		}
		return activeRequest{id: id, original: original, body: redacted.Body, marker: markerFromBody(t, redacted.Body)}
	}
	initialize := func(request activeRequest) {
		instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
			SourceFormat: "claude", Model: "claude-sonnet-5", RequestHeaders: sharedHeaders,
			RequestBody: request.body, Metadata: map[string]any{cpaRequestIDMetadataKey: request.id},
			ChunkIndex: -1,
		})
	}

	first := start("cpa-agent-stream-1", `C:\private\agent-one\chunk0.json`)
	second := start("cpa-agent-stream-2", `C:\private\agent-two\chunk0.json`)
	initialize(first)
	initialize(second)

	event, marshalErr := json.Marshal(map[string]any{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]any{
			"type": "tool_use", "id": "toolu_search", "name": "Search",
			"input": map[string]any{"pattern": "**/" + second.marker + "*"},
		},
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	chunk := append(append([]byte("event: content_block_start\ndata: "), event...), []byte("\n\n")...)
	response := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
		SourceFormat: "claude", Model: "claude-sonnet-5", RequestHeaders: sharedHeaders,
		RequestBody: second.body, Metadata: map[string]any{cpaRequestIDMetadataKey: second.id},
		Body: chunk, ChunkIndex: 0,
	})
	if response.DropChunk || bytes.Contains(response.Body, []byte(second.marker)) || !bytes.Contains(response.Body, []byte(`agent-two`)) {
		t.Fatalf("shared client request header selected the wrong stream session: drop=%v body=%s", response.DropChunk, response.Body)
	}
	if bytes.Contains(response.Body, []byte(`agent-one`)) || bytes.Contains(response.Body, []byte(first.marker)) {
		t.Fatalf("second stream received data from the first session: %s", response.Body)
	}
}

func TestRequestHeaderLookupKeysDoNotAddOrChangeHeaders(t *testing.T) {
	headers := http.Header{
		"X-Client-Request-Id": []string{"client-request-123"},
		"X-Custom-Existing":   []string{"keep-me"},
		"Idempotency-Key":     []string{"reused-operation"},
		"Traceparent":         []string{"reused-trace"},
	}
	prepared := maskForwardedHost(headers)
	if len(prepared) != len(headers) || prepared.Get("X-Client-Request-Id") != "client-request-123" || prepared.Get("X-Custom-Existing") != "keep-me" {
		t.Fatalf("request headers changed: before=%v after=%v", headers, prepared)
	}
	if len(requestHeaderLookupKeys(prepared)) != 1 {
		t.Fatalf("request header lookup keys = %#v", requestHeaderLookupKeys(prepared))
	}
	if keys := requestHeaderLookupKeys(http.Header{"Idempotency-Key": []string{"same"}, "Traceparent": []string{"same"}}); len(keys) != 0 {
		t.Fatalf("weak or reusable headers became session identities: %#v", keys)
	}
	if got := maskForwardedHost(nil); got != nil {
		t.Fatalf("nil request headers became custom upstream headers: %v", got)
	}
}

func TestCPARequestIDRemainsInternalMetadata(t *testing.T) {
	instance, err := newEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	const requestID = "cpa-private-correlation-id"
	response, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
		SourceFormat: "claude", ToFormat: "claude", Model: "claude-sonnet-5",
		Headers:  http.Header{"X-Client-Request-Id": []string{"client-visible-id"}},
		Body:     []byte(`{"messages":[{"role":"user","content":"person@example.com"}]}`),
		Metadata: map[string]any{cpaRequestIDMetadataKey: requestID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(response.Body, []byte(requestID)) {
		t.Fatalf("cpa_request_id leaked into the provider body: %s", response.Body)
	}
	for name, values := range response.Headers {
		if strings.EqualFold(name, cpaRequestIDMetadataKey) {
			t.Fatalf("cpa_request_id became an upstream header: %v", response.Headers)
		}
		for _, value := range values {
			if strings.Contains(value, requestID) {
				t.Fatalf("cpa_request_id leaked into upstream header %q: %q", name, value)
			}
		}
	}
}

func TestEngineFallsBackToRequestBodyWhenResponseAddsRequestID(t *testing.T) {
	instance, err := newEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
	requestBody, err := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": "work in " + windowsPath}}})
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
		SourceFormat: "claude", ToFormat: "claude", Model: "claude-haiku", Body: requestBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	marker := markerFromBody(t, redacted.Body)
	responseHeaders := http.Header{"X-Client-Request-Id": []string{"added-after-request-interceptor"}}
	instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
		SourceFormat: "claude", Model: "claude-haiku", RequestHeaders: responseHeaders,
		OriginalRequest: redacted.Body, RequestBody: redacted.Body, ChunkIndex: -1,
	})
	arguments, err := json.Marshal(map[string]string{"working_directory": marker})
	if err != nil {
		t.Fatal(err)
	}
	split := bytes.Index(arguments, []byte(marker)) + len(marker)/2
	chunk := func(text string) []byte {
		body, marshalErr := json.Marshal(map[string]any{
			"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": text},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return body
	}
	first := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
		SourceFormat: "claude", Model: "claude-haiku", RequestHeaders: responseHeaders,
		OriginalRequest: redacted.Body, RequestBody: redacted.Body, Body: chunk(string(arguments[:split])), ChunkIndex: 0,
	})
	second := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
		SourceFormat: "claude", Model: "claude-haiku", RequestHeaders: responseHeaders,
		OriginalRequest: redacted.Body, RequestBody: redacted.Body, Body: chunk(string(arguments[split:])), ChunkIndex: 1,
	})
	firstEvent, firstOK := decodeStreamFrameEvent(first.Body)
	secondEvent, secondOK := decodeStreamFrameEvent(second.Body)
	if first.DropChunk || second.DropChunk || !firstOK || !secondOK {
		t.Fatalf("body fallback failed: first=%#v second=%#v", first, second)
	}
	joined := firstEvent["delta"].(map[string]any)["partial_json"].(string) + secondEvent["delta"].(map[string]any)["partial_json"].(string)
	var restored map[string]string
	if err := json.Unmarshal([]byte(joined), &restored); err != nil || restored["working_directory"] != windowsPath {
		t.Fatalf("body fallback restored invalid arguments: err=%v body=%s", err, joined)
	}
}

func TestRPCRequestIDCorrelationSurvivesCallbackContextRecreation(t *testing.T) {
	shutdownEngine()
	lifecycle, err := json.Marshal(lifecycleRequest{ConfigYAML: []byte(`enabled: true
privacy_shield:
  enabled: true
  gitleaks: false
  pii_enabled: true
`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handleMethod(methodRegister, lifecycle); err != nil {
		t.Fatal(err)
	}
	defer shutdownEngine()
	originalSender := hostLogSender
	hostLogSender = func([]byte) ([]byte, error) { return []byte(`{"ok":true}`), nil }
	defer func() { hostLogSender = originalSender }()

	const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
	requestBody, err := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "user", "content": "work in " + windowsPath}}})
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"X-Client-Request-Id": []string{"rpc-client-request-1"}}
	requestRPC, err := json.Marshal(requestInterceptRPCRequest{
		RequestInterceptRequest: requestInterceptRequest{
			SourceFormat: "claude", ToFormat: "claude", Model: "claude-haiku", Headers: headers, Body: requestBody,
			Metadata: map[string]any{cpaRequestIDMetadataKey: "request-only-metadata-id"},
		},
		HostCallbackID: "callback-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handleMethod(methodRequestAfter, requestRPC)
	if err != nil {
		t.Fatal(err)
	}
	var requestEnvelope envelope
	if err := json.Unmarshal(raw, &requestEnvelope); err != nil || !requestEnvelope.OK {
		t.Fatalf("request RPC failed: err=%v raw=%s", err, raw)
	}
	var redacted requestInterceptResponse
	if err := json.Unmarshal(requestEnvelope.Result, &redacted); err != nil {
		t.Fatal(err)
	}
	marker := markerFromBody(t, redacted.Body)
	changedOriginal := []byte(`{"body_changed_after_interception":true}`)
	changedRequest := []byte(`{"provider_translated_body":true}`)
	callStream := func(callbackID string, body []byte, chunkIndex int) streamChunkInterceptResponse {
		t.Helper()
		request, marshalErr := json.Marshal(streamChunkInterceptRPCRequest{
			StreamChunkInterceptRequest: streamChunkInterceptRequest{
				SourceFormat: "claude", Model: "claude-haiku", RequestHeaders: redacted.Headers,
				OriginalRequest: changedOriginal, RequestBody: changedRequest, Body: body, ChunkIndex: chunkIndex,
			},
			HostCallbackID: callbackID,
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		responseRaw, callErr := handleMethod(methodResponseStream, request)
		if callErr != nil {
			t.Fatal(callErr)
		}
		var responseEnvelope envelope
		if unmarshalErr := json.Unmarshal(responseRaw, &responseEnvelope); unmarshalErr != nil || !responseEnvelope.OK {
			t.Fatalf("stream RPC failed: err=%v raw=%s", unmarshalErr, responseRaw)
		}
		var response streamChunkInterceptResponse
		if unmarshalErr := json.Unmarshal(responseEnvelope.Result, &response); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		return response
	}
	callStream("callback-init", nil, -1)
	arguments, err := json.Marshal(map[string]string{"working_directory": marker})
	if err != nil {
		t.Fatal(err)
	}
	split := bytes.Index(arguments, []byte(marker)) + len(marker)/2
	makeChunk := func(text string) []byte {
		body, marshalErr := json.Marshal(map[string]any{
			"type": "content_block_delta", "index": 0,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": text},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return body
	}
	first := callStream("callback-chunk-1", makeChunk(string(arguments[:split])), 0)
	second := callStream("callback-chunk-2", makeChunk(string(arguments[split:])), 1)
	if first.DropChunk || second.DropChunk {
		t.Fatalf("RPC restoration dropped a chunk: first=%v second=%v", first.DropChunk, second.DropChunk)
	}
	firstEvent, firstOK := decodeStreamFrameEvent(first.Body)
	secondEvent, secondOK := decodeStreamFrameEvent(second.Body)
	if !firstOK || !secondOK {
		t.Fatalf("RPC restoration returned invalid provider JSON: first=%s second=%s", first.Body, second.Body)
	}
	joined := firstEvent["delta"].(map[string]any)["partial_json"].(string) + secondEvent["delta"].(map[string]any)["partial_json"].(string)
	var restoredArguments map[string]string
	if err := json.Unmarshal([]byte(joined), &restoredArguments); err != nil {
		t.Fatalf("RPC restored invalid tool JSON: %v\n%s", err, joined)
	}
	if restoredArguments["working_directory"] != windowsPath || strings.Contains(joined, marker) {
		t.Fatalf("RPC restoration failed: %s", joined)
	}
}

func TestEngineRestoresNonStreamToolArgumentsFromOriginalRequest(t *testing.T) {
	cfg := testConfig()
	instance, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
	originalRequest, err := json.Marshal(map[string]any{
		"messages": []any{map[string]any{
			"role":    "user",
			"content": "work in " + windowsPath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	redacted, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
		SourceFormat:   "claude",
		ToFormat:       "claude",
		Model:          "claude-opus-4-8",
		RequestedModel: "model-dxt3al",
		Body:           originalRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	marker := markerFromBody(t, redacted.Body)
	arguments, err := json.Marshal(map[string]any{
		"command":           "git checkout -- main.tex",
		"description":       "Revert main.tex to committed version",
		"working_directory": marker,
	})
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := json.Marshal(map[string]any{
		"choices": []any{map[string]any{
			"index": 0,
			"message": map[string]any{
				"role": "assistant",
				"tool_calls": []any{map[string]any{
					"type": "function",
					"function": map[string]any{
						"name":      "Shell",
						"arguments": string(arguments),
					},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// CPA may translate or otherwise rewrite the executed request after this
	// plugin runs. OriginalRequest remains the only byte-identical callback
	// field in that case.
	response := instance.interceptResponse(responseInterceptRequest{
		SourceFormat:    "openai",
		Model:           "claude-opus-4-8",
		RequestedModel:  "model-dxt3al",
		OriginalRequest: originalRequest,
		RequestBody:     []byte(`{"translated":true}`),
		Body:            responseBody,
	})
	if bytes.Contains(response.Body, []byte(marker)) {
		t.Fatalf("marker leaked from non-stream tool arguments: %s", response.Body)
	}
	var outer map[string]any
	if err := json.Unmarshal(response.Body, &outer); err != nil {
		t.Fatalf("restored response is invalid JSON: %v\n%s", err, response.Body)
	}
	argumentsJSON := outer["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)["arguments"].(string)
	var restoredArguments map[string]any
	if err := json.Unmarshal([]byte(argumentsJSON), &restoredArguments); err != nil {
		t.Fatalf("restored tool arguments are invalid JSON: %v\n%s", err, argumentsJSON)
	}
	if restoredArguments["working_directory"] != windowsPath {
		t.Fatalf("working_directory = %q, want %q", restoredArguments["working_directory"], windowsPath)
	}
}

func TestEngineRestoresNonStreamToolArgumentsByMarkerFallback(t *testing.T) {
	cfg := testConfig()
	instance, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
	requestBody, _ := json.Marshal(map[string]string{"prompt": "work in " + windowsPath})
	redacted, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
		SourceFormat: "claude", ToFormat: "claude", Model: "claude-opus-4-8", Body: requestBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	marker := markerFromBody(t, redacted.Body)
	arguments, _ := json.Marshal(map[string]string{"working_directory": marker})
	responseBody, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{
			"message": map[string]any{
				"tool_calls": []any{map[string]any{
					"function": map[string]any{"name": "Shell", "arguments": string(arguments)},
				}},
			},
		}},
	})

	response := instance.interceptResponse(responseInterceptRequest{
		SourceFormat:    "openai",
		Model:           "claude-opus-4-8",
		OriginalRequest: []byte(`{"rewritten_original":true}`),
		RequestBody:     []byte(`{"translated_request":true}`),
		Body:            responseBody,
	})
	if bytes.Contains(response.Body, []byte(marker)) || !bytes.Contains(response.Body, []byte(`ARDLM-survey`)) {
		t.Fatalf("marker fallback did not restore tool arguments: %s", response.Body)
	}
	if status := instance.status(); status.ActiveSessions != 1 || status.ActiveStreams != 0 {
		t.Fatalf("completed response did not retain only its bounded marker cache: %#v", status)
	}
}

func TestEngineMarkerFallbackRestoresOverlappingSessions(t *testing.T) {
	cfg := testConfig()
	instance, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	firstBody := []byte(`{"prompt":"C:\\Users\\alice\\secret"}`)
	secondBody := []byte(`{"prompt":"C:\\Users\\bob\\secret"}`)
	first, firstRedacted, err := redactJSON(context.Background(), firstBody, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	second, secondRedacted, err := redactJSON(context.Background(), secondBody, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	firstMarker := markerFromBody(t, firstRedacted)
	secondMarker := markerFromBody(t, secondRedacted)
	if firstMarker == secondMarker {
		t.Fatalf("overlapping sessions share marker %q", firstMarker)
	}
	instance.storeSession(first, "request-alice")
	instance.storeSession(second, "request-bob")
	arguments, _ := json.Marshal(map[string]string{"working_directory": secondMarker})
	event, _ := json.Marshal(map[string]any{
		"type": "response.function_call_arguments.delta", "item_id": "call-bob", "output_index": 0, "delta": string(arguments),
	})
	streamResponse := instance.interceptStream(streamChunkInterceptRequest{
		SourceFormat: "openai-response",
		Model:        "claude-opus-4-8",
		RequestBody:  []byte(`{"rewritten":true}`),
		Body:         append(append([]byte("data: "), event...), []byte("\n\n")...),
		ChunkIndex:   0,
	})
	if bytes.Contains(streamResponse.Body, []byte(secondMarker)) || bytes.Contains(streamResponse.Body, []byte(`alice`)) || !bytes.Contains(streamResponse.Body, []byte(`bob`)) {
		t.Fatalf("stream marker fallback did not select the matching overlapping session: %s", streamResponse.Body)
	}

	response := instance.interceptResponse(responseInterceptRequest{
		Model:       "claude-opus-4-8",
		RequestBody: []byte(`{"rewritten":true}`),
		Body:        []byte(`{"working_directory":"` + secondMarker + `"}`),
	})
	if bytes.Contains(response.Body, []byte(secondMarker)) || bytes.Contains(response.Body, []byte(`alice`)) || !bytes.Contains(response.Body, []byte(`bob`)) {
		t.Fatalf("marker fallback did not select the matching overlapping session: %s", response.Body)
	}
}

// CPA does not currently inject cpa_request_id. Consequently, two real
// Claude Code requests can have only the same reusable client header. The
// second request must not evict the first request's marker table before the
// first response has arrived.
func TestEngineRetainsSupersededSharedHeaderSessionForMarkerRecovery(t *testing.T) {
	cfg := testConfig()
	instance, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	sharedHeaders := http.Header{"X-Client-Request-Id": []string{"claude-code-shared-turn"}}
	first, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
		SourceFormat: "claude", ToFormat: "claude", Model: "claude-opus-4-8",
		Headers: sharedHeaders, Body: []byte(`{"prompt":"inspect C:\\Users\\alice\\ann0.json"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
		SourceFormat: "claude", ToFormat: "claude", Model: "claude-opus-4-8",
		Headers: sharedHeaders, Body: []byte(`{"prompt":"inspect C:\\Users\\bob\\other.json"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	firstMarker := markerFromBody(t, first.Body)
	secondMarker := markerFromBody(t, second.Body)

	event, err := json.Marshal(map[string]any{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]any{
			"type": "tool_use", "id": "toolu_listing", "name": "Bash",
			"input": map[string]any{
				"command": `ls -la "` + firstMarker + `/ann0.json" 2>/dev/null`,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	chunk := append(append([]byte("event: content_block_start\ndata: "), event...), []byte("\n\n")...)
	instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
		SourceFormat: "claude", Model: "claude-opus-4-8", RequestHeaders: sharedHeaders,
		RequestBody: []byte(`{"translated_request":true}`), ChunkIndex: -1,
	})
	response := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
		SourceFormat: "claude", Model: "claude-opus-4-8", RequestHeaders: sharedHeaders,
		RequestBody: []byte(`{"translated_request":true}`), Body: chunk, ChunkIndex: 0,
	})
	if response.DropChunk || bytes.Contains(response.Body, []byte(firstMarker)) || !bytes.Contains(response.Body, []byte(`C:\\Users\\alice\\ann0.json`)) {
		t.Fatalf("superseded shared-header session was not recovered by marker: drop=%v body=%s", response.DropChunk, response.Body)
	}
	if bytes.Contains(response.Body, []byte(`C:\\Users\\bob\\other.json`)) || bytes.Contains(response.Body, []byte(secondMarker)) {
		t.Fatalf("shared-header alias selected the newer session: %s", response.Body)
	}
}

// A leaked marker can be replayed by Claude Code in a later turn's history.
// message_stop must release stream/header state without discarding the bounded
// mapping cache needed to repair that replay.
func TestEngineRestoresMarkerReplayedAfterCompletedClaudeStream(t *testing.T) {
	instance, err := newEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"X-Client-Request-Id": []string{"claude-code-turn-one"}}
	redacted, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
		SourceFormat: "claude", ToFormat: "claude", Model: "claude-opus-4-8",
		Headers: headers, Body: []byte(`{"prompt":"inspect C:\\Users\\alice\\ann0.json"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	marker := markerFromBody(t, redacted.Body)

	terminal := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
		SourceFormat: "claude", Model: "claude-opus-4-8", RequestHeaders: headers,
		RequestBody: redacted.Body, Body: []byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"), ChunkIndex: 1,
	})
	if terminal.DropChunk {
		t.Fatal("message_stop was unexpectedly dropped")
	}

	event, err := json.Marshal(map[string]any{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]any{
			"type": "tool_use", "id": "toolu_replay", "name": "Bash",
			"input": map[string]any{"command": `ls -la "` + marker + `/ann0.json"`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	replayed := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
		SourceFormat: "claude", Model: "claude-opus-4-8",
		RequestHeaders: http.Header{"X-Client-Request-Id": []string{"claude-code-turn-two"}},
		RequestBody:    []byte(`{"next_turn":true}`),
		Body:           append(append([]byte("event: content_block_start\ndata: "), event...), []byte("\n\n")...),
		ChunkIndex:     0,
	})
	if replayed.DropChunk || bytes.Contains(replayed.Body, []byte(marker)) || !bytes.Contains(replayed.Body, []byte(`C:\\Users\\alice\\ann0.json`)) {
		t.Fatalf("replayed marker was not restored after message_stop: drop=%v body=%s", replayed.DropChunk, replayed.Body)
	}
}

func TestEngineRestoresMarkerReplayedAfterCompletedNonStreamResponse(t *testing.T) {
	instance, err := newEngine(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	firstBody, err := json.Marshal(map[string]string{"prompt": "contact alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"X-Client-Request-Id": []string{"claude-code-nonstream-one"}}
	redacted, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
		SourceFormat: "claude", ToFormat: "claude", Model: "claude-opus-4-8", Headers: headers, Body: firstBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	marker := markerFromBody(t, redacted.Body)
	firstResponseBody, err := json.Marshal(map[string]string{"result": marker})
	if err != nil {
		t.Fatal(err)
	}
	firstResponse := instance.interceptResponse(responseInterceptRequest{
		SourceFormat: "claude", Model: "claude-opus-4-8", RequestHeaders: headers, RequestBody: redacted.Body, Body: firstResponseBody,
	})
	if bytes.Contains(firstResponse.Body, []byte(marker)) || !bytes.Contains(firstResponse.Body, []byte("alice@example.com")) {
		t.Fatalf("first non-stream response was not restored: %s", firstResponse.Body)
	}

	replayedBody, err := json.Marshal(map[string]string{"result": marker})
	if err != nil {
		t.Fatal(err)
	}
	nextRequestBody, err := json.Marshal(map[string]bool{"next_turn": true})
	if err != nil {
		t.Fatal(err)
	}
	replayed := instance.interceptResponse(responseInterceptRequest{
		SourceFormat: "claude", Model: "claude-opus-4-8",
		RequestHeaders: http.Header{"X-Client-Request-Id": []string{"claude-code-nonstream-two"}},
		RequestBody:    nextRequestBody,
		Body:           replayedBody,
	})
	if bytes.Contains(replayed.Body, []byte(marker)) || !bytes.Contains(replayed.Body, []byte("alice@example.com")) {
		t.Fatalf("replayed marker was not restored after non-stream completion: %s", replayed.Body)
	}
	if status := instance.status(); status.ActiveSessions != 1 || status.ActiveStreams != 0 {
		t.Fatalf("non-stream replay cache did not retain exactly one session: %#v", status)
	}
}

// CPA supplies the executed request payload on every stream callback. That
// body is the only request-unique correlation signal available to a dynamic
// plugin when Claude Code reuses X-Client-Request-Id.
func TestEngineUsesRequestBodyBeforeSharedHeaderForAllStreamProtocols(t *testing.T) {
	tests := []struct {
		name   string
		format string
		chunk  func(string, int) []byte
	}{
		{
			name: "Claude input JSON", format: "claude",
			chunk: func(value string, index int) []byte {
				event, _ := json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "input_json_delta", "partial_json": value}})
				return append(append([]byte("event: content_block_delta\ndata: "), event...), []byte("\n\n")...)
			},
		},
		{
			name: "OpenAI Chat arguments", format: "openai",
			chunk: func(value string, index int) []byte {
				event, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"tool_calls": []any{map[string]any{"index": 0, "function": map[string]any{"arguments": value}}}}, "finish_reason": nil}}})
				return append(append([]byte("data: "), event...), []byte("\n\n")...)
			},
		},
		{
			name: "Codex Responses arguments", format: "openai-response",
			chunk: func(value string, index int) []byte {
				event, _ := json.Marshal(map[string]any{"type": "response.function_call_arguments.delta", "item_id": "call-1", "output_index": 0, "delta": value})
				return append(append([]byte("data: "), event...), []byte("\n\n")...)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instance, err := newEngine(testConfig())
			if err != nil {
				t.Fatal(err)
			}
			headers := http.Header{"X-Client-Request-Id": []string{"shared-claude-code-header"}}
			first, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
				SourceFormat: test.format, ToFormat: test.format, Model: "claude-opus-4-8",
				Headers: headers, Body: []byte(`{"prompt":"inspect C:\\Users\\alice\\ann0.json"}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = instance.interceptAfter(context.Background(), requestInterceptRequest{
				SourceFormat: test.format, ToFormat: test.format, Model: "claude-opus-4-8",
				Headers: headers, Body: []byte(`{"prompt":"inspect C:\\Users\\bob\\other.json"}`),
			})
			if err != nil {
				t.Fatal(err)
			}
			marker := markerFromBody(t, first.Body)
			split := len(marker) / 2
			lookupKeys := correlationLookupKeys(headers, nil, [][]byte{first.Body}, "claude-opus-4-8")
			instance.mu.Lock()
			selected := instance.findSessionLocked(lookupKeys)
			instance.mu.Unlock()
			if selected == nil || selected.byMarker[marker].Marker != marker {
				t.Fatalf("request-body lookup did not select first mapping: marker=%q keys=%v", marker, lookupKeys)
			}
			// CPA sends this initialization callback before the first SSE event.
			instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
				SourceFormat: test.format, Model: "claude-opus-4-8", RequestHeaders: headers,
				RequestBody: first.Body, ChunkIndex: -1,
			})
			firstOut := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
				SourceFormat: test.format, Model: "claude-opus-4-8", RequestHeaders: headers,
				RequestBody: first.Body, Body: test.chunk(marker[:split], 0), ChunkIndex: 0,
			})
			if bytes.Contains(firstOut.Body, []byte(marker[:split])) {
				t.Fatalf("partial marker leaked before completion: %s", firstOut.Body)
			}
			secondOut := instance.interceptStreamContext(context.Background(), streamChunkInterceptRequest{
				SourceFormat: test.format, Model: "claude-opus-4-8", RequestHeaders: headers,
				RequestBody: first.Body, Body: test.chunk(marker[split:], 1), ChunkIndex: 1,
			})
			if secondOut.DropChunk || bytes.Contains(secondOut.Body, []byte(marker)) || !bytes.Contains(secondOut.Body, []byte(`ann0.json`)) {
				t.Fatalf("request-body correlation did not restore split marker: drop=%v body=%s", secondOut.DropChunk, secondOut.Body)
			}
			if bytes.Contains(secondOut.Body, []byte(`other.json`)) {
				t.Fatalf("shared header selected the wrong request body session: %s", secondOut.Body)
			}
		})
	}
}

func TestUnknownBundledEventsNeverBypassMarkerRecovery(t *testing.T) {
	tests := []struct {
		name   string
		format string
		chunk  func(string) []byte
	}{
		{
			name: "Claude", format: "claude",
			chunk: func(marker string) []byte {
				known := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n")
				unknown := []byte("event: future_event\ndata: {\"type\":\"future_event\",\"payload\":{\"command\":\"" + marker + "\"}}\n\n")
				return append(known, unknown...)
			},
		},
		{
			name: "OpenAI Chat", format: "openai",
			chunk: func(marker string) []byte {
				known := []byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\n")
				unknown := []byte("data: {\"event\":\"future_event\",\"payload\":{\"command\":\"" + marker + "\"}}\n\n")
				return append(known, unknown...)
			},
		},
		{
			name: "Codex Responses", format: "openai-response",
			chunk: func(marker string) []byte {
				known := []byte("data: {\"type\":\"response.output_text.delta\",\"item_id\":\"item-1\",\"output_index\":0,\"content_index\":0,\"delta\":\"ok\"}\n\n")
				unknown := []byte("data: {\"type\":\"response.future_event\",\"payload\":{\"command\":\"" + marker + "\"}}\n\n")
				return append(known, unknown...)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newPrivacySession()
			marker := session.newMarker("future-event")
			session.addMapping(mapping{Marker: marker, Original: `private-project/ann0.json`})
			restorer := &streamRestorer{session: session, adapter: adapterForFormat(test.format)}
			output, drop, count := restorer.feed(test.chunk(marker))
			if drop || count != 1 || bytes.Contains(output, []byte(marker)) || !bytes.Contains(output, []byte(`private-project/ann0.json`)) {
				t.Fatalf("unknown bundled event leaked marker: drop=%v count=%d body=%s", drop, count, output)
			}
		})
	}
}

func TestUnknownStreamEventsCarrySplitMarkersForAllProtocols(t *testing.T) {
	tests := []struct {
		name   string
		format string
		chunk  func(string) []byte
	}{
		{
			name: "Claude", format: "claude",
			chunk: func(value string) []byte {
				event, _ := json.Marshal(map[string]any{"type": "future_event", "index": 0, "payload": map[string]any{"command": value}})
				return append(append([]byte("event: future_event\ndata: "), event...), []byte("\n\n")...)
			},
		},
		{
			name: "OpenAI Chat", format: "openai",
			chunk: func(value string) []byte {
				event, _ := json.Marshal(map[string]any{"event": "future_event", "index": 0, "payload": map[string]any{"command": value}})
				return append(append([]byte("data: "), event...), []byte("\n\n")...)
			},
		},
		{
			name: "Codex Responses", format: "openai-response",
			chunk: func(value string) []byte {
				event, _ := json.Marshal(map[string]any{"type": "response.future_event", "item_id": "item-1", "output_index": 0, "payload": map[string]any{"command": value}})
				return append(append([]byte("data: "), event...), []byte("\n\n")...)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newPrivacySession()
			marker := markerPrefix + "AAAAAAAABBBBC"
			session.addMapping(mapping{Marker: marker, Original: "private-project/ann0.json"})
			restorer := &streamRestorer{session: session, adapter: adapterForFormat(test.format)}
			split := len(marker) / 2

			first, firstDrop, firstCount := restorer.feed(test.chunk(marker[:split]))
			if firstDrop || firstCount != 0 || bytes.Contains(first, []byte(marker[:split])) {
				t.Fatalf("unknown event leaked an incomplete marker: drop=%v count=%d body=%s", firstDrop, firstCount, first)
			}
			second, secondDrop, secondCount := restorer.feed(test.chunk(marker[split:]))
			if secondDrop || secondCount != 1 || bytes.Contains(second, []byte(marker)) || !bytes.Contains(second, []byte("private-project/ann0.json")) {
				t.Fatalf("unknown event did not restore its split marker: drop=%v count=%d body=%s", secondDrop, secondCount, second)
			}
		})
	}
}

func TestEngineRestoresToolArgumentStreamsByMarkerFallback(t *testing.T) {
	tests := []struct {
		name   string
		format string
		chunk  func(string) []byte
		field  func(map[string]any) string
	}{
		{
			name: "OpenAI Chat", format: "openai",
			chunk: func(arguments string) []byte {
				event, _ := json.Marshal(map[string]any{
					"choices": []any{map[string]any{
						"index": 0,
						"delta": map[string]any{"tool_calls": []any{map[string]any{
							"index": 0, "function": map[string]any{"arguments": arguments},
						}}},
						"finish_reason": nil,
					}},
				})
				return append(append([]byte("data: "), event...), []byte("\n\n")...)
			},
			field: func(event map[string]any) string {
				return event["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)["arguments"].(string)
			},
		},
		{
			name: "Claude", format: "claude",
			chunk: func(arguments string) []byte {
				event, _ := json.Marshal(map[string]any{
					"type": "content_block_delta", "index": 0,
					"delta": map[string]any{"type": "input_json_delta", "partial_json": arguments},
				})
				return append(append([]byte("event: content_block_delta\ndata: "), event...), []byte("\n\n")...)
			},
			field: func(event map[string]any) string {
				return event["delta"].(map[string]any)["partial_json"].(string)
			},
		},
		{
			name: "Codex Responses", format: "codex",
			chunk: func(arguments string) []byte {
				event, _ := json.Marshal(map[string]any{
					"type": "response.function_call_arguments.delta", "item_id": "call-1", "output_index": 0, "delta": arguments,
				})
				return append(append([]byte("data: "), event...), []byte("\n\n")...)
			},
			field: func(event map[string]any) string { return event["delta"].(string) },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			instance, err := newEngine(cfg)
			if err != nil {
				t.Fatal(err)
			}
			const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
			requestBody, _ := json.Marshal(map[string]string{"prompt": "work in " + windowsPath})
			redacted, err := instance.interceptAfter(context.Background(), requestInterceptRequest{
				SourceFormat: "claude", ToFormat: "claude", Model: "claude-opus-4-8", Body: requestBody,
			})
			if err != nil {
				t.Fatal(err)
			}
			marker := markerFromBody(t, redacted.Body)
			arguments, _ := json.Marshal(map[string]string{"working_directory": marker})
			chunk := test.chunk(string(arguments))
			response := instance.interceptStream(streamChunkInterceptRequest{
				SourceFormat:    test.format,
				Model:           "claude-opus-4-8",
				OriginalRequest: []byte(`{"rewritten_original":true}`),
				RequestBody:     []byte(`{"translated_request":true}`),
				Body:            chunk,
				ChunkIndex:      0,
			})
			if response.DropChunk || bytes.Contains(response.Body, []byte(marker)) {
				t.Fatalf("stream marker leaked or chunk dropped: drop=%v body=%s", response.DropChunk, response.Body)
			}
			dataIndex := bytes.Index(response.Body, []byte("data: "))
			if dataIndex < 0 {
				t.Fatalf("restored stream has no data event: %s", response.Body)
			}
			data := response.Body[dataIndex+len("data: "):]
			if end := bytes.Index(data, []byte("\n")); end >= 0 {
				data = data[:end]
			}
			var event map[string]any
			if err := json.Unmarshal(data, &event); err != nil {
				t.Fatalf("restored stream event is invalid JSON: %v\n%s", err, response.Body)
			}
			var restoredArguments map[string]string
			if err := json.Unmarshal([]byte(test.field(event)), &restoredArguments); err != nil {
				t.Fatalf("restored stream arguments are invalid JSON: %v\n%s", err, test.field(event))
			}
			if restoredArguments["working_directory"] != windowsPath {
				t.Fatalf("working_directory = %q, want %q", restoredArguments["working_directory"], windowsPath)
			}
		})
	}
}

func TestRequestInterceptorsMaskForwardedHost(t *testing.T) {
	cfg := testConfig()
	instance, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request := requestInterceptRequest{
		Model:   "claude-fable-5",
		Headers: http.Header{"X-Forwarded-Host": []string{"private.gateway.example"}},
		Body:    []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	}

	before, err := instance.interceptBefore(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if got := before.Headers.Get("X-Forwarded-Host"); got != "api.anthropic.com" {
		t.Fatalf("before-auth X-Forwarded-Host = %q, want api.anthropic.com", got)
	}
	if got := request.Headers.Get("X-Forwarded-Host"); got != "private.gateway.example" {
		t.Fatalf("input headers were mutated: %q", got)
	}

	request.Headers = before.Headers
	after, err := instance.interceptAfter(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.Headers.Get("X-Forwarded-Host"); got != "api.anthropic.com" {
		t.Fatalf("after-auth X-Forwarded-Host = %q, want api.anthropic.com", got)
	}
}

func TestBuildPluginExposesOfficialSDKCapabilities(t *testing.T) {
	plugin, err := buildPlugin([]byte("enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if plugin.Metadata.Name != "CPA Sensitive" || plugin.Metadata.Version != cpaSensitivePluginVersion {
		t.Fatalf("unexpected plugin metadata: %#v", plugin.Metadata)
	}
	if plugin.Capabilities.RequestInterceptor == nil || plugin.Capabilities.ResponseInterceptor == nil || plugin.Capabilities.StreamChunkInterceptor == nil || plugin.Capabilities.ManagementAPI == nil {
		t.Fatalf("official CPA capabilities are incomplete: %#v", plugin.Capabilities)
	}
	if _, ok := plugin.Capabilities.RequestInterceptor.(pluginapi.RequestInterceptor); !ok {
		t.Fatalf("request interceptor does not implement pluginapi.RequestInterceptor: %T", plugin.Capabilities.RequestInterceptor)
	}
}

func TestEngineEmitsSafeRedactionActivity(t *testing.T) {
	cfg := defaultConfig()
	cfg.Enabled = true
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	instance, err := newEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var events []activityEvent
	ctx := withActivityLogger(context.Background(), func(event activityEvent) {
		events = append(events, event)
	})
	metadata := map[string]any{cpaRequestIDMetadataKey: "request-safe-log"}
	request := requestInterceptRequest{
		Model: "claude-haiku", SourceFormat: "codex", ToFormat: "claude",
		Body:     []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"person@example.com"}]}]}`),
		Metadata: metadata,
	}
	_, err = instance.interceptAfter(ctx, request)
	if err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 {
		t.Fatalf("activity events = %d, want one redaction event", len(events))
	}
	if events[0].Stage != "request.redacted" || events[0].Count != 1 || events[0].RequestID != "request-safe-log" {
		t.Fatalf("redaction activity = %#v", events[0])
	}
}

func TestRPCForwardsSafeActivityToHostLogger(t *testing.T) {
	shutdownEngine()
	lifecycle, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte(`enabled: true
privacy_shield:
  enabled: true
  gitleaks: false
  pii_enabled: true
`)})
	if _, err := handleMethod(methodRegister, lifecycle); err != nil {
		t.Fatal(err)
	}
	defer shutdownEngine()

	originalSender := hostLogSender
	defer func() { hostLogSender = originalSender }()
	var captured hostLogRequest
	hostLogSender = func(payload []byte) ([]byte, error) {
		if err := json.Unmarshal(payload, &captured); err != nil {
			t.Fatal(err)
		}
		return []byte(`{"ok":true}`), nil
	}

	request, _ := json.Marshal(requestInterceptRPCRequest{
		RequestInterceptRequest: requestInterceptRequest{
			Model: "claude-haiku", SourceFormat: "codex", ToFormat: "claude",
			Body:     []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"person@example.com"}]}]}`),
			Metadata: map[string]any{cpaRequestIDMetadataKey: "request-host-log"},
		},
		HostCallbackID: "callback-safe-log",
	})
	if _, err := handleMethod(methodRequestAfter, request); err != nil {
		t.Fatal(err)
	}

	if captured.HostCallbackID != "callback-safe-log" || !strings.HasPrefix(captured.Message, "SensitivePromptMasker request.redacted count=1 source=codex target=claude stream=false") {
		t.Fatalf("captured host log = %#v", captured)
	}
	if captured.Fields["count"] != float64(1) || captured.Fields["request_id"] != "request-host-log" {
		t.Fatalf("captured host log fields = %#v", captured.Fields)
	}
	ruleCounts, ok := captured.Fields["rule_counts"].(map[string]any)
	if !ok || ruleCounts["pii-email"] != float64(1) {
		t.Fatalf("captured rule counts = %#v, want pii-email=1", captured.Fields["rule_counts"])
	}
	if !strings.Contains(captured.Message, "rules=pii-email:1") {
		t.Fatalf("captured host log message lacks safe rule histogram: %q", captured.Message)
	}
	raw, _ := json.Marshal(captured)
	if strings.Contains(string(raw), "person@example.com") || strings.Contains(string(raw), legacyMarkerPrefix) ||
		strings.Contains(string(raw), compactLegacyMarkerPrefix) || strings.Contains(string(raw), markerPrefix) {
		t.Fatalf("host activity log leaked sensitive content: %s", raw)
	}
}

func TestPrivacyMarkersAreCompactUniqueAndStableAcrossRetries(t *testing.T) {
	first := newPrivacySession()
	markerA := first.newMarker("rule-a\x00secret-a")
	first.Mappings = append(first.Mappings, mapping{Marker: markerA, Original: "secret-a", RuleID: "rule-a"})
	markerB := first.newMarker("rule-b\x00secret-b")
	first.Mappings = append(first.Mappings, mapping{Marker: markerB, Original: "secret-b", RuleID: "rule-b"})

	if len(markerA) > 32 || len(markerB) > 32 {
		t.Fatalf("markers are not compact: len(a)=%d len(b)=%d", len(markerA), len(markerB))
	}
	if markerA == markerB {
		t.Fatalf("different mappings share marker %q", markerA)
	}
	if !strings.HasPrefix(markerA, markerPrefix) || !strings.HasPrefix(markerB, markerPrefix) {
		t.Fatalf("compact marker prefix missing: %q %q", markerA, markerB)
	}

	second := newPrivacySession()
	markerOtherSession := second.newMarker("rule-a\x00secret-a")
	if markerOtherSession != markerA {
		t.Fatalf("same sensitive value changed marker across retries: first=%q second=%q", markerA, markerOtherSession)
	}
}

func TestPrivacyMarkerUsesOnlyASCIIAlphanumericCharacters(t *testing.T) {
	marker := newPrivacySession().newMarker("$/messages/0/content\x00pii-path\x000")
	if marker == "" {
		t.Fatal("marker is empty")
	}
	for _, char := range marker {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			continue
		}
		t.Fatalf("marker %q contains non-alphanumeric character %q", marker, char)
	}
}

func TestRestoreSupportsPreviousMarkerFormats(t *testing.T) {
	compactLegacy := compactLegacyMarkerPrefix + "ABCDEFGHIJKLM" + "_"
	longLegacy := legacyMarkerPrefix + "0123456789abcdef0123456789abcdef"
	session := newPrivacySession()
	session.Mappings = []mapping{
		{Marker: compactLegacy, Original: `d:\legacy\compact`},
		{Marker: longLegacy, Original: `d:\legacy\long`},
	}
	body, _ := json.Marshal(map[string]string{
		"compact": compactLegacy,
		"long":    longLegacy,
	})
	restored, count := restoreJSONBytes(body, session)
	if count != 2 || bytes.Contains(restored, []byte(compactLegacy)) || bytes.Contains(restored, []byte(longLegacy)) {
		t.Fatalf("previous marker formats were not restored: count=%d body=%s", count, restored)
	}
}

func BenchmarkRestoreContentManyMappings(b *testing.B) {
	session := newPrivacySession()
	for index := 0; index < 560; index++ {
		original := fmt.Sprintf("secret-%06d", index)
		marker := session.newMarker(fmt.Sprintf("rule-%d\x00%s", index, original))
		session.Mappings = append(session.Mappings, mapping{Marker: marker, Original: original, RuleID: fmt.Sprintf("rule-%d", index)})
	}
	body := []byte(`{"type":"content_block_delta","delta":{"type":"text_delta","text":"prefix ` + session.Mappings[559].Marker + ` suffix"}}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		out, count := restoreContentBytes(body, session)
		if count != 1 || !bytes.Contains(out, []byte("secret-000559")) {
			b.Fatalf("restore failed: count=%d body=%s", count, out)
		}
	}
}

func TestPrivacyShieldPreservesProtocolStructuralFields(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	cfg.Privacy.PII.Phone = boolPointer(true)
	cfg.Privacy.PII.UUID = boolPointer(true)
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{
  "model":"claude-haiku-4-5-20251001",
  "context_management":{"edits":[{"type":"clear_thinking_20251015"}]},
  "messages":[{"role":"user","content":"phone 20251015 email person@example.com"}],
  "tools":[{"name":"lookup_20251015","input_schema":{"type":"object"}}],
  "id":"3744369f-0055-4a7d-9d52-9065be04e5e4",
  "call_id":"call_20251015"
}`)
	session, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	text := string(redacted)
	for _, structural := range []string{
		`"model":"claude-haiku-4-5-20251001"`,
		`"type":"clear_thinking_20251015"`,
		`"role":"user"`,
		`"name":"lookup_20251015"`,
		`"type":"object"`,
		`"id":"3744369f-0055-4a7d-9d52-9065be04e5e4"`,
		`"call_id":"call_20251015"`,
	} {
		if !strings.Contains(text, structural) {
			t.Fatalf("protocol structural field was modified: want %s in %s", structural, redacted)
		}
	}
	if !strings.Contains(text, markerPrefix) || strings.Contains(text, "person@example.com") {
		t.Fatalf("content field was not redacted: %s", redacted)
	}
	if len(session.Mappings) == 0 {
		t.Fatal("content redaction produced no mappings")
	}
}

func TestPrivacyShieldPreservesOpaqueAndToolReferenceFields(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	cfg.Privacy.PII.Email = boolPointer(true)
	cfg.Privacy.PII.GenericToken = boolPointer(true)
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}

	const (
		toolName      = "mcp__nia__manage_resource_20260716"
		thinkingSig   = "EqQBCgIYAhIM1v2OWHGt6N4LQxZ0LongThinkingSignature20260716"
		redactedData  = "EqQBCgIYAhIMOpaqueRedactedThinkingPayload20260716"
		base64Payload = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ20260716"
	)
	body := []byte(`{
  "messages":[
    {"role":"assistant","content":[
      {"type":"thinking","thinking":"email person@example.com","signature":"` + thinkingSig + `"},
      {"type":"redacted_thinking","data":"` + redactedData + `"}
    ]},
    {"role":"user","content":[
      {"type":"tool_result","tool_use_id":"toolu_20260716","content":[
        {"type":"tool_reference","tool_name":"` + toolName + `"},
        {"type":"image","source":{"type":"base64","media_type":"image/png","data":"` + base64Payload + `"}},
        {"type":"text","text":"email result@example.com"}
      ]}
    ]}
  ],
  "tools":[{"name":"` + toolName + `","input_schema":{"type":"object"}}]
}`)

	session, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	text := string(redacted)
	for _, opaque := range []string{toolName, thinkingSig, redactedData, base64Payload} {
		if !strings.Contains(text, opaque) {
			t.Fatalf("opaque protocol value was modified: want %q in %s", opaque, redacted)
		}
	}
	if !strings.Contains(text, "person@example.com") {
		t.Fatalf("signed thinking text was modified: %s", redacted)
	}
	if strings.Contains(text, "result@example.com") {
		t.Fatalf("tool-result text was not redacted: %s", redacted)
	}
	if len(session.Mappings) != 1 {
		t.Fatalf("mapping count = %d, want only the unsigned tool-result email; mappings=%#v", len(session.Mappings), session.Mappings)
	}
}

func TestPrivacyShieldPreservesSignedThinkingAndRedactsToolPayloadFields(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	cfg.Privacy.PII.Email = boolPointer(true)
	cfg.Privacy.PII.BankCard = boolPointer(true)
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{
  "messages":[{"role":"assistant","content":[
    {"type":"thinking","thinking":"email signed@example.com","signature":"E-valid-signature"},
    {"type":"tool_use","id":"toolu_1","name":"lookup","input":{
      "name":"person@example.com",
      "account_id":"4111111111111111",
		"status":"result@example.com",
		"fake_thinking":{"type":"thinking","signature":"business-signature","email":"fake-thinking@example.com"},
		"record":{"type":"message","name":"record@example.com","account_id":"5555555555554444","status":"record-status@example.com"},
		"fake_image":{"type":"input_image","image_url":"https://fake-image@example.com/private.png"}
    }}
  ]}]
}`)
	_, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	text := string(redacted)
	if !strings.Contains(text, "email signed@example.com") || !strings.Contains(text, "E-valid-signature") {
		t.Fatalf("signed thinking block was modified: %s", redacted)
	}
	for _, sensitive := range []string{
		"person@example.com", "4111111111111111", "result@example.com",
		"fake-thinking@example.com", "record@example.com", "5555555555554444",
		"record-status@example.com", "https://fake-image@example.com/private.png",
	} {
		if strings.Contains(text, sensitive) {
			t.Fatalf("tool payload field was not redacted: %q in %s", sensitive, redacted)
		}
	}
}

func TestPrivacyShieldPreservesOpenAIMediaPayloads(t *testing.T) {
	cfg := defaultConfig()
	cfg.Privacy.Enabled = true
	cfg.Privacy.Gitleaks = boolPointer(false)
	cfg.Privacy.PIIEnabled = boolPointer(true)
	cfg.Privacy.PII.Email = boolPointer(true)
	cfg.Privacy.PII.GenericToken = boolPointer(true)
	detector, err := newDetector(cfg.Privacy)
	if err != nil {
		t.Fatal(err)
	}

	const (
		imageURL  = "https://person@example.com/private.png"
		fileData  = "data:application/pdf;base64,VGhpcy1pcy1hLWxvbmctZmlsZS1wYXlsb2FkLTIwMjYwNzE2"
		chatData  = "data:image/png;base64,aVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQUFFQUFBQUJDQVlBQUFBZkZjU0oyMDI2MDcxNg=="
		fileWrap  = "data:application/zip;base64,VGhpcy1pcy1hLW5lc3RlZC1maWxlLXdyYXBwZXItMjAyNjA3MTY="
		audioData = "VGhpcy1pcy1uZXN0ZWQtYXVkaW8tZGF0YS0yMDI2MDcxNg=="
		videoData = "data:video/mp4;base64,VGhpcy1pcy1uZXN0ZWQtdmlkZW8tZGF0YS0yMDI2MDcxNg=="
	)
	body := []byte(`{
  "input":[{"type":"message","role":"user","content":[
    {"type":"input_image","image_url":"` + imageURL + `"},
    {"type":"input_file","file_data":"` + fileData + `","filename":"report.pdf"}
  ]}],
  "messages":[{"role":"user","content":[
	{"type":"image_url","image_url":{"url":"` + chatData + `"}},
	{"type":"file","file":{"file_data":"` + fileWrap + `","filename":"archive.zip"}},
	{"type":"input_audio","input_audio":{"data":"` + audioData + `","format":"wav"}},
	{"type":"video_url","video_url":{"url":"` + videoData + `"}}
  ]}]
}`)
	_, redacted, err := redactJSON(context.Background(), body, cfg.Privacy, detector)
	if err != nil {
		t.Fatal(err)
	}
	text := string(redacted)
	for _, payload := range []string{imageURL, fileData, chatData, fileWrap, audioData, videoData} {
		if !strings.Contains(text, payload) {
			t.Fatalf("media payload was modified: want %q in %s", payload, redacted)
		}
	}
}

func TestRestoreJSONBytesEscapesWindowsPathInsideNonStreamToolArguments(t *testing.T) {
	const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
	session := newPrivacySession()
	marker := session.newMarker("path\x00" + windowsPath)
	session.Mappings = append(session.Mappings, mapping{Marker: marker, Original: windowsPath, RuleID: "path"})

	inner, err := json.Marshal(map[string]string{"working_directory": marker})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"choices": []any{map[string]any{
			"message": map[string]any{
				"tool_calls": []any{map[string]any{
					"function": map[string]any{"arguments": string(inner)},
				}},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	restored, count := restoreJSONBytes(body, session)
	if count != 1 {
		t.Fatalf("restore count = %d, want 1; body=%s", count, restored)
	}
	var outer map[string]any
	if err := json.Unmarshal(restored, &outer); err != nil {
		t.Fatalf("restored response is invalid JSON: %v\n%s", err, restored)
	}
	argumentsJSON := outer["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)["arguments"].(string)
	var arguments map[string]any
	if err := json.Unmarshal([]byte(argumentsJSON), &arguments); err != nil {
		t.Fatalf("restored tool arguments are invalid JSON: %v\n%s", err, argumentsJSON)
	}
	if arguments["working_directory"] != windowsPath {
		t.Fatalf("working_directory = %q, want %q", arguments["working_directory"], windowsPath)
	}
}

func TestRestoreJSONBytesTreatsClaudeToolInputArgumentsAsPlainString(t *testing.T) {
	const windowsPath = `d:\OneDrive\paper\ARDLM-survey`
	session := newPrivacySession()
	marker := session.newMarker("plain-tool-input")
	session.Mappings = []mapping{{Marker: marker, Original: windowsPath}}
	body := []byte(`{"content":[{"type":"tool_use","id":"toolu_1","name":"run","input":{"type":"function_call","arguments":"` + marker + `"}}]}`)

	restored, count := restoreJSONBytes(body, session)
	if count != 1 {
		t.Fatalf("restore count = %d, want 1; body=%s", count, restored)
	}
	var root map[string]any
	if err := json.Unmarshal(restored, &root); err != nil {
		t.Fatal(err)
	}
	got := root["content"].([]any)[0].(map[string]any)["input"].(map[string]any)["arguments"]
	if got != windowsPath {
		t.Fatalf("plain arguments field = %q, want %q", got, windowsPath)
	}
}

func TestClaudeContentBlockStartRestoresCompleteToolInput(t *testing.T) {
	const originalPattern = `**/private-project/chunk0*`
	session := newPrivacySession()
	marker := session.newMarker("complete-claude-tool-input")
	session.Mappings = []mapping{{Marker: marker, Original: originalPattern}}
	restorer := &streamRestorer{session: session, adapter: adapterForFormat("claude")}

	event, err := json.Marshal(map[string]any{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]any{
			"type": "tool_use",
			"id":   "toolu_search",
			"name": "Search",
			"input": map[string]any{
				"pattern": "**/" + marker + "*",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	chunk := append(append([]byte("event: content_block_start\ndata: "), event...), []byte("\n\n")...)

	restored, drop, count := restorer.feed(chunk)
	if drop || count != 1 {
		t.Fatalf("complete Claude tool input was not restored: drop=%v count=%d body=%s", drop, count, restored)
	}
	if bytes.Contains(restored, []byte(marker)) || !bytes.Contains(restored, []byte(originalPattern)) {
		t.Fatalf("complete Claude tool input leaked marker: %s", restored)
	}
}

func TestClaudeBundledStartAndDeltaRestoresToolInput(t *testing.T) {
	const originalPath = `/c/Users/Arc/.claude/projects/example/memory`
	session := newPrivacySession()
	marker := session.newMarker("bundled-claude-tool-start")
	session.Mappings = []mapping{{Marker: marker, Original: originalPath}}
	restorer := &streamRestorer{session: session, adapter: adapterForFormat("claude")}

	start, err := json.Marshal(map[string]any{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]any{
			"type": "tool_use",
			"id":   "toolu_bash",
			"name": "Bash",
			"input": map[string]any{
				"command": `D="` + marker + `"; cat "$D/no-find-command.md"`,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := json.Marshal(map[string]any{
		"type": "content_block_delta", "index": 1,
		"delta": map[string]any{"type": "text_delta", "text": "running command"},
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(append(append([]byte("event: content_block_start\ndata: "), start...), []byte("\n\n")...), append(append([]byte("event: content_block_delta\ndata: "), delta...), []byte("\n\n")...)...)

	restored, drop, count := restorer.feed(bundle)
	if drop || count != 1 {
		t.Fatalf("bundled Claude tool input was not restored: drop=%v count=%d body=%s", drop, count, restored)
	}
	if bytes.Contains(restored, []byte(marker)) || !bytes.Contains(restored, []byte(originalPath)) {
		t.Fatalf("bundled Claude content_block_start leaked marker: %s", restored)
	}
}

func TestCodexResponseIncompleteIsTerminal(t *testing.T) {
	if !adapterForFormat("codex").StreamTerminal([]byte(`data: {"type":"response.incomplete","response":{"status":"incomplete"}}`)) {
		t.Fatal("Codex response.incomplete was not recognized as terminal")
	}
}

func TestCodexResponseDoneIsTerminal(t *testing.T) {
	if !adapterForFormat("codex").StreamTerminal([]byte(`data: {"type":"response.done","response":{"status":"completed"}}`)) {
		t.Fatal("Codex response.done was not recognized as terminal")
	}
}

func TestRPCRegistrationAndCodexRequestPath(t *testing.T) {
	shutdownEngine()
	lifecycle, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte(`enabled: true
sanitization:
  enabled: true
  replacement_groups:
    - models: ["gpt-*"]
      source_formats: ["codex"]
      replacements:
        - src: Claude Code
          dst: client
privacy_shield:
  enabled: false
`)})
	raw, err := handleMethod(methodRegister, lifecycle)
	if err != nil {
		t.Fatal(err)
	}
	var registered envelope
	if err := json.Unmarshal(raw, &registered); err != nil || !registered.OK {
		t.Fatalf("registration envelope invalid: err=%v raw=%s", err, raw)
	}
	var result registration
	if err := json.Unmarshal(registered.Result, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Capabilities.RequestInterceptor || !result.Capabilities.ResponseInterceptor || !result.Capabilities.StreamChunkInterceptor {
		t.Fatalf("registration missing interceptor capabilities: %#v", result.Capabilities)
	}
	request, _ := json.Marshal(requestInterceptRequest{SourceFormat: "codex", Model: "gpt-5", Body: []byte(`{"instructions":"Claude Code"}`)})
	raw, err = handleMethod(methodRequestBefore, request)
	if err != nil {
		t.Fatal(err)
	}
	var intercepted envelope
	_ = json.Unmarshal(raw, &intercepted)
	var response requestInterceptResponse
	_ = json.Unmarshal(intercepted.Result, &response)
	if !strings.Contains(string(response.Body), "client") {
		t.Fatalf("Codex request did not pass through compatibility adapter: %s", response.Body)
	}
}

func markerFromBody(t *testing.T, body []byte) string {
	t.Helper()
	start := strings.Index(string(body), markerPrefix)
	if start < 0 {
		t.Fatalf("marker missing: %s", body)
	}
	end := start + len(markerPrefix)
	if end >= len(body) {
		t.Fatalf("compact marker is truncated: %s", body)
	}
	for end < len(body) && isMarkerBase32Char(body[end]) {
		end++
	}
	if end == start+len(markerPrefix) {
		t.Fatalf("marker digest missing: %s", body)
	}
	return string(body[start:end])
}

func intPointer(value int) *int { return &value }
