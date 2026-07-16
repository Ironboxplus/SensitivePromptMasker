package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type jsonStringEdit struct {
	start       int
	end         int
	replacement []byte
}

type jsonStringRewriter struct {
	body  []byte
	edits []jsonStringEdit
}

func rewriteJSONStrings(body []byte, original, redacted any) ([]byte, error) {
	rewriter := jsonStringRewriter{body: body}
	position := 0
	if err := rewriter.walkValue(&position, original, redacted); err != nil {
		return nil, err
	}
	rewriter.skipSpace(&position)
	if position != len(body) {
		return nil, fmt.Errorf("privacy JSON rewrite stopped at byte %d of %d", position, len(body))
	}
	if len(rewriter.edits) == 0 {
		return body, nil
	}
	var output bytes.Buffer
	last := 0
	for _, edit := range rewriter.edits {
		if edit.start < last || edit.end < edit.start || edit.end > len(body) {
			return nil, fmt.Errorf("privacy JSON rewrite produced invalid edit [%d:%d]", edit.start, edit.end)
		}
		output.Write(body[last:edit.start])
		output.Write(edit.replacement)
		last = edit.end
	}
	output.Write(body[last:])
	return output.Bytes(), nil
}

func (r *jsonStringRewriter) walkValue(position *int, original, redacted any) error {
	r.skipSpace(position)
	if *position >= len(r.body) {
		return fmt.Errorf("privacy JSON rewrite reached unexpected end of input")
	}
	switch r.body[*position] {
	case '"':
		originalString, originalOK := original.(string)
		redactedString, redactedOK := redacted.(string)
		if !originalOK || !redactedOK {
			return fmt.Errorf("privacy JSON rewrite found string with incompatible semantic values")
		}
		start := *position
		end, decoded, err := r.scanString(start)
		if err != nil {
			return err
		}
		if decoded != originalString {
			return fmt.Errorf("privacy JSON rewrite string mismatch at byte %d", start)
		}
		if redactedString != originalString {
			replacement, errMarshal := marshalJSON(redactedString)
			if errMarshal != nil {
				return errMarshal
			}
			r.edits = append(r.edits, jsonStringEdit{start: start, end: end, replacement: replacement})
		}
		*position = end
		return nil
	case '{':
		originalMap, originalOK := original.(map[string]any)
		redactedMap, redactedOK := redacted.(map[string]any)
		if !originalOK || !redactedOK {
			return fmt.Errorf("privacy JSON rewrite found object with incompatible semantic values")
		}
		return r.walkObject(position, originalMap, redactedMap)
	case '[':
		originalList, originalOK := original.([]any)
		redactedList, redactedOK := redacted.([]any)
		if !originalOK || !redactedOK || len(originalList) != len(redactedList) {
			return fmt.Errorf("privacy JSON rewrite found array with incompatible semantic values")
		}
		return r.walkArray(position, originalList, redactedList)
	default:
		return r.skipPrimitive(position)
	}
}

func (r *jsonStringRewriter) walkObject(position *int, original, redacted map[string]any) error {
	(*position)++
	r.skipSpace(position)
	if *position < len(r.body) && r.body[*position] == '}' {
		(*position)++
		return nil
	}
	for {
		r.skipSpace(position)
		if *position >= len(r.body) || r.body[*position] != '"' {
			return fmt.Errorf("privacy JSON rewrite expected object key at byte %d", *position)
		}
		end, key, err := r.scanString(*position)
		if err != nil {
			return err
		}
		*position = end
		r.skipSpace(position)
		if *position >= len(r.body) || r.body[*position] != ':' {
			return fmt.Errorf("privacy JSON rewrite expected colon at byte %d", *position)
		}
		(*position)++
		originalChild, originalExists := original[key]
		redactedChild, redactedExists := redacted[key]
		if !originalExists || !redactedExists {
			return fmt.Errorf("privacy JSON rewrite could not resolve object key %q", key)
		}
		if err := r.walkValue(position, originalChild, redactedChild); err != nil {
			return err
		}
		r.skipSpace(position)
		if *position >= len(r.body) {
			return fmt.Errorf("privacy JSON rewrite reached unexpected end of object")
		}
		switch r.body[*position] {
		case ',':
			(*position)++
		case '}':
			(*position)++
			return nil
		default:
			return fmt.Errorf("privacy JSON rewrite expected object delimiter at byte %d", *position)
		}
	}
}

func (r *jsonStringRewriter) walkArray(position *int, original, redacted []any) error {
	(*position)++
	r.skipSpace(position)
	if *position < len(r.body) && r.body[*position] == ']' {
		(*position)++
		return nil
	}
	for index := range original {
		if err := r.walkValue(position, original[index], redacted[index]); err != nil {
			return err
		}
		r.skipSpace(position)
		if index+1 < len(original) {
			if *position >= len(r.body) || r.body[*position] != ',' {
				return fmt.Errorf("privacy JSON rewrite expected array delimiter at byte %d", *position)
			}
			(*position)++
			continue
		}
		if *position >= len(r.body) || r.body[*position] != ']' {
			return fmt.Errorf("privacy JSON rewrite expected array end at byte %d", *position)
		}
		(*position)++
		return nil
	}
	return fmt.Errorf("privacy JSON rewrite found empty semantic array with non-empty JSON")
}

func (r *jsonStringRewriter) scanString(start int) (int, string, error) {
	if start >= len(r.body) || r.body[start] != '"' {
		return start, "", fmt.Errorf("privacy JSON rewrite expected string at byte %d", start)
	}
	for position := start + 1; position < len(r.body); position++ {
		switch r.body[position] {
		case '\\':
			position++
			if position >= len(r.body) {
				return start, "", fmt.Errorf("privacy JSON rewrite found truncated escape at byte %d", position-1)
			}
		case '"':
			end := position + 1
			var decoded string
			if err := json.Unmarshal(r.body[start:end], &decoded); err != nil {
				return start, "", fmt.Errorf("privacy JSON rewrite decoded string at byte %d: %w", start, err)
			}
			return end, decoded, nil
		}
	}
	return start, "", fmt.Errorf("privacy JSON rewrite found unterminated string at byte %d", start)
}

func (r *jsonStringRewriter) skipPrimitive(position *int) error {
	start := *position
	for *position < len(r.body) {
		switch r.body[*position] {
		case ' ', '\t', '\r', '\n', ',', ']', '}':
			if *position == start {
				return fmt.Errorf("privacy JSON rewrite expected primitive at byte %d", start)
			}
			return nil
		default:
			(*position)++
		}
	}
	if *position == start {
		return fmt.Errorf("privacy JSON rewrite expected primitive at byte %d", start)
	}
	return nil
}

func (r *jsonStringRewriter) skipSpace(position *int) {
	for *position < len(r.body) {
		switch r.body[*position] {
		case ' ', '\t', '\r', '\n':
			(*position)++
		default:
			return
		}
	}
}
