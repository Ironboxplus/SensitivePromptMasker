# SensitivePromptMasker

[简体中文](README_CN.md) | English

Repository: https://github.com/Ironboxplus/SensitivePromptMasker

`cpa-sensitive` is a standalone CLIProxyAPI C-ABI plugin extracted from the
Octopus prompt sanitization and Privacy Shield work. CPA itself only supplies
the public interceptor lifecycle and a stable `cpa_request_id` metadata value.

The plugin uses the official CLIProxyAPI dynamic-plugin SDK and is loaded as a
native `.so`, `.dylib`, or `.dll`. The C ABI is only the shared-library boundary;
the interceptor, detection, marker, session, compatibility, and restoration
logic is implemented in Go.

Verified protocol surfaces include:

- OpenAI Chat Completions, including streaming content, reasoning, and tool arguments.
- Anthropic/Claude Messages, including `text`, `thinking`, and `partial_json` deltas.
- OpenAI/Codex Responses, including output-text and function-call-argument deltas.
- Provider-native JSON chunks received behind a different client `SourceFormat`.

The top-level compatibility layer selects an explicit adapter from CPA's
`SourceFormat` / `ToFormat`: Claude handles `system`, Anthropic message content,
and `content_block_delta` / `message_stop`; Codex handles Responses-style
`instructions`, `input`, `response.output_text.delta`, function-call argument
deltas, and `response.completed`. OpenAI Chat uses the generic chat adapter.
The replacement, detector, marker, and state code remains protocol-neutral.

The plugin runs in four stages:

1. `request.intercept_before`: apply ordered literal replacements to system,
   developer, assistant, and Gemini `model` text fields.
2. `request.intercept_after`: scan the final provider payload with Gitleaks,
   built-in PII rules, and optional custom regular expressions; replace findings
   with request-scoped markers.
3. `response.intercept_after`: restore markers in non-stream JSON responses.
4. `response.intercept_stream_chunk`: restore complete and cross-chunk markers
   while preserving JSON escaping.

Octopus `replacement_groups`, legacy `system_prompt_replacements`, `models`,
`src`, `dst`, and `order` retain their meaning. CPA adds `source_formats` and
`to_formats`; groups with `to_formats` run in the post-auth adapter before
Privacy Shield. Legacy `base_urls` are
accepted so config migration is visible, but the group is not activated until
it is converted because CPA's public interceptor ABI does not expose credential
endpoint URLs.

Octopus `pii_types`, `pii_aggressive`, `pii_aggressive_types`,
`debug_cache_ttl_seconds`, and body/string/finding limits are accepted. The
legacy debug TTL becomes the restoration session TTL unless
`session.ttl_seconds` is set. Octopus per-channel `channels` cannot be mapped
because CPA interceptor callbacks do not carry an Octopus channel ID; enable or
disable the CPA plugin instance instead.

## Installation

Download or build the library for the CPA host platform, then place it under
CPA's plugin directory using the stable plugin name:

```text
plugins/linux/amd64/cpa-sensitive.so
plugins/darwin/arm64/cpa-sensitive.dylib
plugins/windows/amd64/cpa-sensitive.dll
```

Enable the global plugin host and add a `cpa-sensitive` configuration block.
CPA discovers and loads the library on startup. Runtime status is exposed at:

```text
/v0/resource/plugins/cpa-sensitive/status
```

Example configuration:

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    cpa-sensitive:
      enabled: true
      priority: 10
      sanitization:
        enabled: true
        replacement_groups:
          - id: client-fingerprint
            models: ["gpt-*", "claude-*"]
            source_formats: ["openai", "openai-response", "claude"]
            replacements:
              - id: claude-code-name
                src: "Claude Code"
                dst: "AI coding client"
                order: 10
      privacy_shield:
        enabled: true
        pii_enabled: true
        max_body_bytes: 1048576
        max_string_bytes: 262144
        max_findings: 0
        pii_types:
          gitleaks: true
          email: true
          phone: true
          national_id: true
          bank_card: true
          ip: true
          jwt: true
          uuid: true
          credential_url: true
          mac_address: true
          ipv6: true
          path: true
          generic_token: false
        pii_aggressive: false
        pii_aggressive_types:
          relative_path: false
          username_hostname: false
          generic_token: false
          loose_secret: false
        custom_rules:
          - id: internal-token
            description: Internal token syntax
            regex: 'secret_[A-Za-z0-9]{24,}'
      session:
        ttl_seconds: 86400
        max_sessions: 4096
```

`pii_aggressive: true` enables relative-path, username/hostname, 24-character
generic-token, and loosely-labelled-secret detection. This is intentionally
high recall and can mask ordinary source-code paths, random identifiers, or test
fixtures. Prefer the standard PII/Gitleaks rules first unless that false-positive
tradeoff is acceptable.

To explicitly enable every detector, set every `pii_types` and
`pii_aggressive_types` field to `true`, and set both `gitleaks` and
`pii_enabled` to `true`.

## Logging boundary

The plugin masks data before the provider request and restores it before the
client response. CPA's optional detailed request logger sits outside that
boundary and can record the original inbound body and the restored outbound
body. For production privacy, disable detailed request logs:

```yaml
request-log: false
```

Normal service logging can remain enabled. The plugin's `/status` resource
reports aggregate mapping/restoration counters without logging detected secret
values. Redaction and restoration activity is also written through CPA's
official `host.log` callback, so it appears in **Logs Viewer** with runtime
`CPA`. These entries contain only stage, count, model, protocol, request ID, and
stream state; they never contain request bodies, original values, or markers.

Build for the current platform:

```bash
go mod tidy
go test ./...
go build -buildmode=c-shared -o cpa-sensitive.so .
```

Use `.dll` on Windows and `.dylib` on macOS. The generated C header is not
required at runtime.

`make build VERSION=0.1.2` provides the same native build with release metadata.
Pushing a `v*` tag runs the repository workflow, builds supported platform
archives, writes SHA-256 files, and publishes a GitHub release.

## Acknowledgements

The plugin ABI behavior was aligned against CLIProxyAPI's official SDK and the
official [`cpa-plugin-jshandler`](https://github.com/router-for-me/cpa-plugin-jshandler)
reference implementation. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
for the release-helper attribution.
