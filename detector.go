package main

import (
	"context"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	gitleaksdetect "github.com/zricethezav/gitleaks/v8/detect"
)

type compositeDetector struct{ detectors []detector }

func newDetector(cfg privacyShieldConfig) (detector, error) {
	var detectors []detector
	patterns := builtinPatterns(cfg)
	for _, rule := range cfg.CustomRules {
		compiled, err := regexp.Compile(rule.Regex)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, regexRule{id: rule.ID, description: rule.Description, pattern: compiled, secretGroup: rule.SecretGroup})
	}
	if len(patterns) != 0 {
		detectors = append(detectors, regexDetector{rules: patterns})
	}
	if boolValue(cfg.Gitleaks) {
		instance, err := gitleaksdetect.NewDetectorDefaultConfig()
		if err != nil {
			return nil, err
		}
		detectors = append(detectors, gitleaksDetector{detector: instance})
	}
	return compositeDetector{detectors: detectors}, nil
}

func (d compositeDetector) DetectString(ctx context.Context, value string) ([]finding, error) {
	var out []finding
	for _, child := range d.detectors {
		findings, err := child.DetectString(ctx, value)
		if err != nil {
			return nil, err
		}
		out = append(out, findings...)
	}
	return out, nil
}

type regexRule struct {
	id          string
	description string
	pattern     *regexp.Regexp
	secretGroup int
	validate    func(string) bool
}

type regexDetector struct{ rules []regexRule }

func (d regexDetector) DetectString(_ context.Context, value string) ([]finding, error) {
	var out []finding
	for _, rule := range d.rules {
		for _, indexes := range rule.pattern.FindAllStringSubmatchIndex(value, -1) {
			group := rule.secretGroup
			if group < 0 || group*2+1 >= len(indexes) || indexes[group*2] < 0 {
				group = 0
			}
			start, end := indexes[group*2], indexes[group*2+1]
			secret := value[start:end]
			if rule.validate != nil && !rule.validate(secret) {
				continue
			}
			out = append(out, finding{Start: start, End: end, RuleID: rule.id, Description: rule.description})
		}
	}
	return out, nil
}

func builtinPatterns(privacy privacyShieldConfig) []regexRule {
	cfg := privacy.PII
	var rules []regexRule
	add := func(enabled *bool, id, description, pattern string, group int, validate func(string) bool) {
		if boolValue(enabled) {
			rules = append(rules, regexRule{id: id, description: description, pattern: regexp.MustCompile(pattern), secretGroup: group, validate: validate})
		}
	}
	add(cfg.Email, "pii-email", "email address", `[A-Za-z0-9.!#$%&'*+/=?^_`+"`"+`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+`, 0, nil)
	add(cfg.Phone, "pii-phone", "phone number", `(?:^|[^0-9A-Za-z])((?:\+?[0-9]{1,3}[- .]?)?(?:\(?[0-9]{2,4}\)?[- .]?){2,5}[0-9]{2,4})(?:$|[^0-9A-Za-z])`, 1, validPhone)
	add(cfg.NationalID, "pii-national-id-cn", "Chinese national ID", `(?:^|[^0-9A-Za-z])([1-9][0-9]{16}[0-9Xx])(?:$|[^0-9A-Za-z])`, 1, validCNID)
	add(cfg.BankCard, "pii-bank-card", "bank card number", `(?:^|[^0-9])([0-9][0-9 -]{11,28}[0-9])(?:$|[^0-9])`, 1, validLuhn)
	add(cfg.IP, "pii-ipv4", "IPv4 address", `(?:^|[^0-9A-Za-z])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:$|[^0-9A-Za-z])`, 1, validIP)
	add(cfg.JWT, "pii-jwt", "JSON web token", `(?:^|[^A-Za-z0-9_-])([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{16,})(?:$|[^A-Za-z0-9_-])`, 1, nil)
	add(cfg.UUID, "pii-uuid", "UUID", `(?:^|[^0-9A-Fa-f])([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12})(?:$|[^0-9A-Fa-f])`, 1, nil)
	add(cfg.CredentialURL, "pii-credential-url", "URL containing credentials", `\b([a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@:]+:[^\s/@]+@[^\s]+)`, 1, nil)
	add(cfg.MACAddress, "pii-mac-address", "MAC address", `(?:^|[^0-9A-Fa-f])([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5})(?:$|[^0-9A-Fa-f])`, 1, nil)
	add(cfg.IPv6, "pii-ipv6", "IPv6 address", `[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:.]{2,}`, 0, validIPv6)
	add(cfg.Path, "pii-path", "local filesystem path", `(?i)(?:[A-Z]:[\\/](?:[^\\/\s\"'<>|?*]+[\\/])*[^\\/\s\"'<>|?*]+|/(?:home|Users|root|var|etc|opt|usr|srv|tmp|mnt|workspace|data)(?:/[A-Za-z0-9._@+:-]+)+)`, 0, nil)
	add(cfg.GenericToken, "pii-generic-token", "generic high-entropy token", `\b[A-Za-z0-9_\-]{32,}\b`, 0, validGenericToken)
	aggressive := privacy.PIIAggressive
	add(boolPointer(aggressive || boolValue(privacy.PIIAggressiveTypes.RelativePath)), "pii-relative-path", "relative filesystem path", `(?:^|[\s\"'`+"`"+`({\[])((?:\.{1,2}[\\/])(?:[A-Za-z0-9._@+:-]+[\\/])*[A-Za-z0-9._@+:-]+)`, 1, nil)
	add(boolPointer(aggressive || boolValue(privacy.PIIAggressiveTypes.UsernameHostname)), "pii-username-hostname", "username and hostname", `\b([A-Za-z_][A-Za-z0-9._-]{1,31}@[A-Za-z0-9][A-Za-z0-9.-]{1,253})\b`, 1, nil)
	add(boolPointer(aggressive || boolValue(privacy.PIIAggressiveTypes.GenericToken)), "pii-generic-token-aggressive", "generic high-entropy token", `\b[A-Za-z0-9_\-]{24,}\b`, 0, validGenericToken)
	add(boolPointer(aggressive || boolValue(privacy.PIIAggressiveTypes.LooseSecret)), "pii-loose-secret", "loosely labeled secret", `(?i)(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[\"']?([^\s\"']{8,})`, 1, nil)
	return rules
}

func validGenericToken(value string) bool {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "mcp__") {
		return false
	}
	return value != lower || !isWordLikeIdentifier(lower)
}

func isWordLikeIdentifier(value string) bool {
	if !strings.ContainsAny(value, "_-") {
		return false
	}
	parts := strings.FieldsFunc(value, func(char rune) bool {
		return char == '_' || char == '-'
	})
	if len(parts) < 2 {
		return false
	}
	alphabeticParts := 0
	for _, part := range parts {
		if part == "" {
			continue
		}
		lettersOnly := true
		for _, char := range part {
			if char < 'a' || char > 'z' {
				lettersOnly = false
				break
			}
		}
		if lettersOnly && len(part) >= 2 {
			alphabeticParts++
		}
	}
	return alphabeticParts >= 2
}

type gitleaksDetector struct{ detector *gitleaksdetect.Detector }

func (d gitleaksDetector) DetectString(ctx context.Context, value string) ([]finding, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	results := d.detector.DetectContext(ctx, gitleaksdetect.Fragment{Raw: value})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []finding
	for _, result := range results {
		if result.Secret == "" {
			continue
		}
		start, end, ok := byteOffsetFromFinding(value, result.StartLine, result.StartColumn, result.Line, result.Secret)
		if !ok {
			continue
		}
		out = append(out, finding{Start: start, End: end, RuleID: result.RuleID, Description: result.Description})
	}
	return out, nil
}

func byteOffsetFromFinding(value string, startLine, startColumn int, line, secret string) (int, int, bool) {
	if secret == "" {
		return 0, 0, false
	}
	lineStart, ok := byteOffsetForLine(value, startLine)
	if !ok {
		lineStart = 0
	}
	searchStart := lineStart
	if startColumn > 0 && lineStart+startColumn-1 <= len(value) {
		searchStart = lineStart + startColumn - 1
	}
	if index := strings.Index(value[searchStart:], secret); index >= 0 {
		start := searchStart + index
		return start, start + len(secret), true
	}
	if line != "" {
		if lineSecret := strings.Index(line, secret); lineSecret >= 0 {
			if rawLine := strings.Index(value[lineStart:], line); rawLine >= 0 {
				start := lineStart + rawLine + lineSecret
				return start, start + len(secret), true
			}
		}
	}
	if index := strings.Index(value, secret); index >= 0 {
		return index, index + len(secret), true
	}
	return 0, 0, false
}

func byteOffsetForLine(value string, line int) (int, bool) {
	if line < 0 {
		return 0, false
	}
	if line == 0 {
		return 0, true
	}
	offset := 0
	for index := 0; index < line; index++ {
		next := strings.IndexByte(value[offset:], '\n')
		if next < 0 {
			return 0, false
		}
		offset += next + 1
	}
	return offset, true
}

func validPhone(value string) bool {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, value)
	if len(digits) == 8 {
		if _, err := time.Parse("20060102", digits); err == nil {
			return false
		}
	}
	return len(digits) >= 7 && len(digits) <= 15
}

func validIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4()
}

func validIPv6(value string) bool {
	address, err := netip.ParseAddr(strings.Trim(value, "[]"))
	return err == nil && address.Is6()
}

func validLuhn(value string) bool {
	digits := strings.NewReplacer(" ", "", "-", "").Replace(value)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, parity := 0, len(digits)%2
	for index, char := range digits {
		if char < '0' || char > '9' {
			return false
		}
		digit := int(char - '0')
		if index%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

func validCNID(value string) bool {
	if len(value) != 18 {
		return false
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := "10X98765432"
	sum := 0
	for index := 0; index < 17; index++ {
		digit, err := strconv.Atoi(value[index : index+1])
		if err != nil {
			return false
		}
		sum += digit * weights[index]
	}
	return strings.EqualFold(value[17:], checks[sum%11:sum%11+1])
}
