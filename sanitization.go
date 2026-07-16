package main

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

type orderedReplacement struct {
	src   string
	dst   string
	order int
	seq   int
}

func sanitizeRequest(body []byte, cfg sanitizationConfig, model, sourceFormat, toFormat string) ([]byte, int, error) {
	return sanitizeRequestForStage(body, cfg, model, sourceFormat, toFormat, false)
}

func sanitizeRequestAfterAuth(body []byte, cfg sanitizationConfig, model, sourceFormat, toFormat string) ([]byte, int, error) {
	return sanitizeRequestForStage(body, cfg, model, sourceFormat, toFormat, true)
}

func sanitizeRequestForStage(body []byte, cfg sanitizationConfig, model, sourceFormat, toFormat string, afterAuth bool) ([]byte, int, error) {
	if !cfg.Enabled || len(cfg.ReplacementGroups) == 0 || len(body) == 0 {
		return body, 0, nil
	}
	rules := matchingReplacements(cfg, model, sourceFormat, toFormat, afterAuth)
	if len(rules) == 0 {
		return body, 0, nil
	}
	root, err := decodeJSON(body)
	if err != nil {
		return nil, 0, err
	}
	// request.intercept_after runs after credential selection but before CPA
	// translates the payload. toFormat selects provider-scoped rules; the body
	// is still in the original client format and must use the source adapter.
	count := sanitizeProtocolRequest(root, rules, sourceFormat)
	if count == 0 {
		return body, 0, nil
	}
	out, err := marshalJSON(root)
	return out, count, err
}

func matchingReplacements(cfg sanitizationConfig, model, sourceFormat, toFormat string, afterAuth bool) []orderedReplacement {
	var out []orderedReplacement
	seq := 0
	for _, group := range cfg.ReplacementGroups {
		if afterAuth != (len(group.ToFormats) != 0) {
			continue
		}
		if !matchesAnyOrEmpty(group.Models, model) || !matchesAnyOrEmpty(group.SourceFormats, sourceFormat) || !matchesAnyOrEmpty(group.ToFormats, toFormat) {
			continue
		}
		// Octopus base_urls cannot be evaluated through CPA's public interceptor
		// contract. Do not silently broaden a legacy URL-scoped rule.
		if len(group.BaseURLs) != 0 {
			continue
		}
		for index, item := range group.Replacements {
			if item.Src == "" {
				continue
			}
			order := index
			if item.Order != nil {
				order = *item.Order
			}
			out = append(out, orderedReplacement{src: item.Src, dst: item.Dst, order: order, seq: seq})
			seq++
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].order == out[j].order {
			return out[i].seq < out[j].seq
		}
		return out[i].order < out[j].order
	})
	return out
}

func sanitizeNode(value any, rules []orderedReplacement) int {
	switch node := value.(type) {
	case map[string]any:
		count := 0
		role, _ := node["role"].(string)
		if sanitizableRole(role) {
			for _, key := range []string{"content", "text", "parts", "reasoning", "reasoning_content"} {
				if child, ok := node[key]; ok {
					updated, n := sanitizeTextContainer(child, rules, true)
					node[key] = updated
					count += n
				}
			}
		}
		for _, key := range []string{"system", "instructions", "systemInstruction", "system_instruction"} {
			if child, ok := node[key]; ok {
				updated, n := sanitizeTextContainer(child, rules, true)
				node[key] = updated
				count += n
			}
		}
		for key, child := range node {
			switch key {
			case "content", "text", "parts", "reasoning", "reasoning_content", "system", "instructions", "systemInstruction", "system_instruction":
				continue
			}
			count += sanitizeNode(child, rules)
		}
		return count
	case []any:
		count := 0
		for _, child := range node {
			count += sanitizeNode(child, rules)
		}
		return count
	default:
		return 0
	}
}

func sanitizeTextContainer(value any, rules []orderedReplacement, allowString bool) (any, int) {
	switch node := value.(type) {
	case string:
		if !allowString {
			return node, 0
		}
		return applyLiteralReplacements(node, rules)
	case []any:
		count := 0
		for index, child := range node {
			updated, n := sanitizeTextContainer(child, rules, true)
			node[index] = updated
			count += n
		}
		return node, count
	case map[string]any:
		count := 0
		for key, child := range node {
			allowed := key == "text" || key == "content" || key == "input_text" || key == "output_text" || key == "parts"
			updated, n := sanitizeTextContainer(child, rules, allowed)
			node[key] = updated
			count += n
		}
		return node, count
	default:
		return value, 0
	}
}

func applyLiteralReplacements(text string, rules []orderedReplacement) (string, int) {
	result := text
	count := 0
	for _, rule := range rules {
		if !strings.Contains(result, rule.src) {
			continue
		}
		count += strings.Count(result, rule.src)
		result = strings.ReplaceAll(result, rule.src, rule.dst)
	}
	return result, count
}

func sanitizableRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "system", "developer", "assistant", "model":
		return true
	default:
		return false
	}
}

func matchesAnyOrEmpty(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if globMatch(pattern, value) {
			return true
		}
	}
	return false
}

func globMatch(pattern, value string) bool {
	patternIndex, valueIndex := 0, 0
	starIndex, starValueIndex := -1, -1
	for valueIndex < len(value) {
		if patternIndex < len(pattern) && (pattern[patternIndex] == '?' || pattern[patternIndex] == value[valueIndex]) {
			patternIndex++
			valueIndex++
			continue
		}
		if patternIndex < len(pattern) && pattern[patternIndex] == '*' {
			starIndex = patternIndex
			starValueIndex = valueIndex
			patternIndex++
			continue
		}
		if starIndex >= 0 {
			patternIndex = starIndex + 1
			starValueIndex++
			valueIndex = starValueIndex
			continue
		}
		return false
	}
	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(pattern)
}

func decodeJSON(body []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	return root, nil
}

func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
