package main

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultSessionTTLSeconds = 24 * 60 * 60
	defaultMaxSessions       = 4096
	defaultMaxBodyBytes      = 1 << 20
	defaultMaxStringBytes    = 256 << 10
)

type config struct {
	Enabled      bool                `yaml:"enabled" json:"enabled"`
	Priority     int                 `yaml:"priority" json:"priority"`
	Sanitization sanitizationConfig  `yaml:"sanitization" json:"sanitization"`
	Privacy      privacyShieldConfig `yaml:"privacy_shield" json:"privacy_shield"`
	Session      sessionConfig       `yaml:"session" json:"session"`
}

type sessionConfig struct {
	TTLSeconds  int `yaml:"ttl_seconds" json:"ttl_seconds"`
	MaxSessions int `yaml:"max_sessions" json:"max_sessions"`
}

type sanitizationConfig struct {
	Enabled                   bool               `yaml:"enabled" json:"enabled"`
	TokenUsageRecoveryEnabled bool               `yaml:"token_usage_recovery_enabled,omitempty" json:"token_usage_recovery_enabled,omitempty"`
	ReplacementGroups         []replacementGroup `yaml:"replacement_groups" json:"replacement_groups"`
	Replacements              []replacementRule  `yaml:"system_prompt_replacements,omitempty" json:"system_prompt_replacements,omitempty"`
}

// replacementGroup preserves Octopus' model filter and ordered replacement
// shape, while adding CPA-native source/to protocol filters. BaseURLs is read
// for migration diagnostics but cannot be evaluated because CPA's public
// interceptor ABI intentionally does not expose credential endpoint URLs.
type replacementGroup struct {
	ID            string        `yaml:"id,omitempty" json:"id,omitempty"`
	Models        []string      `yaml:"models" json:"models"`
	BaseURLs      []string      `yaml:"base_urls,omitempty" json:"base_urls,omitempty"`
	SourceFormats []string      `yaml:"source_formats,omitempty" json:"source_formats,omitempty"`
	ToFormats     []string      `yaml:"to_formats,omitempty" json:"to_formats,omitempty"`
	Replacements  []replacement `yaml:"replacements" json:"replacements"`
}

type replacement struct {
	ID    string `yaml:"id,omitempty" json:"id,omitempty"`
	Src   string `yaml:"src" json:"src"`
	Dst   string `yaml:"dst" json:"dst"`
	Order *int   `yaml:"order,omitempty" json:"order,omitempty"`
}

type replacementRule struct {
	ID            string   `yaml:"id,omitempty" json:"id,omitempty"`
	Models        []string `yaml:"models" json:"models"`
	BaseURLs      []string `yaml:"base_urls,omitempty" json:"base_urls,omitempty"`
	SourceFormats []string `yaml:"source_formats,omitempty" json:"source_formats,omitempty"`
	ToFormats     []string `yaml:"to_formats,omitempty" json:"to_formats,omitempty"`
	Src           string   `yaml:"src" json:"src"`
	Dst           string   `yaml:"dst" json:"dst"`
}

type privacyShieldConfig struct {
	Enabled              bool                     `yaml:"enabled" json:"enabled"`
	Gitleaks             *bool                    `yaml:"gitleaks,omitempty" json:"gitleaks,omitempty"`
	PIIEnabled           *bool                    `yaml:"pii_enabled,omitempty" json:"pii_enabled,omitempty"`
	PIIAggressive        bool                     `yaml:"pii_aggressive,omitempty" json:"pii_aggressive,omitempty"`
	PIIAggressiveTypes   piiAggressiveTypesConfig `yaml:"pii_aggressive_types,omitempty" json:"pii_aggressive_types,omitempty"`
	DebugCacheTTLSeconds int                      `yaml:"debug_cache_ttl_seconds,omitempty" json:"debug_cache_ttl_seconds,omitempty"`
	MaxBodyBytes         int                      `yaml:"max_body_bytes" json:"max_body_bytes"`
	MaxStringBytes       int                      `yaml:"max_string_bytes" json:"max_string_bytes"`
	MaxFindings          int                      `yaml:"max_findings" json:"max_findings"`
	PII                  piiConfig                `yaml:"pii" json:"pii"`
	PIITypes             piiConfig                `yaml:"pii_types,omitempty" json:"pii_types,omitempty"`
	CustomRules          []detectorRule           `yaml:"custom_rules,omitempty" json:"custom_rules,omitempty"`
}

type piiConfig struct {
	Gitleaks      *bool `yaml:"gitleaks,omitempty" json:"gitleaks,omitempty"`
	Email         *bool `yaml:"email,omitempty" json:"email,omitempty"`
	Phone         *bool `yaml:"phone,omitempty" json:"phone,omitempty"`
	NationalID    *bool `yaml:"national_id,omitempty" json:"national_id,omitempty"`
	BankCard      *bool `yaml:"bank_card,omitempty" json:"bank_card,omitempty"`
	IP            *bool `yaml:"ip,omitempty" json:"ip,omitempty"`
	JWT           *bool `yaml:"jwt,omitempty" json:"jwt,omitempty"`
	UUID          *bool `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	CredentialURL *bool `yaml:"credential_url,omitempty" json:"credential_url,omitempty"`
	MACAddress    *bool `yaml:"mac_address,omitempty" json:"mac_address,omitempty"`
	IPv6          *bool `yaml:"ipv6,omitempty" json:"ipv6,omitempty"`
	Path          *bool `yaml:"path,omitempty" json:"path,omitempty"`
	GenericToken  *bool `yaml:"generic_token,omitempty" json:"generic_token,omitempty"`
}

type piiAggressiveTypesConfig struct {
	RelativePath     *bool `yaml:"relative_path,omitempty" json:"relative_path,omitempty"`
	UsernameHostname *bool `yaml:"username_hostname,omitempty" json:"username_hostname,omitempty"`
	GenericToken     *bool `yaml:"generic_token,omitempty" json:"generic_token,omitempty"`
	LooseSecret      *bool `yaml:"loose_secret,omitempty" json:"loose_secret,omitempty"`
}

type detectorRule struct {
	ID          string `yaml:"id" json:"id"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Regex       string `yaml:"regex" json:"regex"`
	SecretGroup int    `yaml:"secret_group,omitempty" json:"secret_group,omitempty"`
}

func defaultConfig() config {
	return config{
		Session: sessionConfig{TTLSeconds: defaultSessionTTLSeconds, MaxSessions: defaultMaxSessions},
		Privacy: privacyShieldConfig{
			Gitleaks:       boolPointer(true),
			PIIEnabled:     boolPointer(true),
			MaxBodyBytes:   defaultMaxBodyBytes,
			MaxStringBytes: defaultMaxStringBytes,
			PII: piiConfig{
				Email: boolPointer(true), Phone: boolPointer(true), NationalID: boolPointer(true),
				BankCard: boolPointer(true), IP: boolPointer(true), JWT: boolPointer(true),
				UUID: boolPointer(true), CredentialURL: boolPointer(true), MACAddress: boolPointer(true),
				IPv6: boolPointer(true), Path: boolPointer(true), GenericToken: boolPointer(false),
			},
		},
	}
}

func parseConfig(raw []byte) (config, error) {
	cfg := config{}
	if len(strings.TrimSpace(string(raw))) != 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return config{}, fmt.Errorf("decode cpa-sensitive config: %w", err)
		}
	}
	cfg.normalize()
	return cfg, nil
}

func (c *config) normalize() {
	if c.Session.TTLSeconds <= 0 {
		c.Session.TTLSeconds = c.Privacy.DebugCacheTTLSeconds
		if c.Session.TTLSeconds <= 0 {
			c.Session.TTLSeconds = defaultSessionTTLSeconds
		}
	}
	if c.Session.MaxSessions <= 0 {
		c.Session.MaxSessions = defaultMaxSessions
	}
	if c.Privacy.MaxBodyBytes <= 0 {
		c.Privacy.MaxBodyBytes = defaultMaxBodyBytes
	}
	if c.Privacy.MaxStringBytes <= 0 {
		c.Privacy.MaxStringBytes = defaultMaxStringBytes
	}
	if c.Privacy.MaxFindings < 0 {
		c.Privacy.MaxFindings = 0
	}
	defaults := defaultConfig().Privacy
	c.normalizeLegacySanitization()
	c.Privacy.PII.mergeMissing(c.Privacy.PIITypes)
	if c.Privacy.Gitleaks == nil && c.Privacy.PIITypes.Gitleaks != nil {
		c.Privacy.Gitleaks = boolPointer(boolValue(c.Privacy.PIITypes.Gitleaks))
	}
	fillBool(&c.Privacy.Gitleaks, defaults.Gitleaks)
	fillBool(&c.Privacy.PIIEnabled, defaults.PIIEnabled)
	fillBool(&c.Privacy.PII.Email, defaults.PII.Email)
	fillBool(&c.Privacy.PII.Phone, defaults.PII.Phone)
	fillBool(&c.Privacy.PII.NationalID, defaults.PII.NationalID)
	fillBool(&c.Privacy.PII.BankCard, defaults.PII.BankCard)
	fillBool(&c.Privacy.PII.IP, defaults.PII.IP)
	fillBool(&c.Privacy.PII.JWT, defaults.PII.JWT)
	fillBool(&c.Privacy.PII.UUID, defaults.PII.UUID)
	fillBool(&c.Privacy.PII.CredentialURL, defaults.PII.CredentialURL)
	fillBool(&c.Privacy.PII.MACAddress, defaults.PII.MACAddress)
	fillBool(&c.Privacy.PII.IPv6, defaults.PII.IPv6)
	fillBool(&c.Privacy.PII.Path, defaults.PII.Path)
	fillBool(&c.Privacy.PII.GenericToken, defaults.PII.GenericToken)
	fillBool(&c.Privacy.PIIAggressiveTypes.RelativePath, boolPointer(false))
	fillBool(&c.Privacy.PIIAggressiveTypes.UsernameHostname, boolPointer(false))
	fillBool(&c.Privacy.PIIAggressiveTypes.GenericToken, boolPointer(false))
	fillBool(&c.Privacy.PIIAggressiveTypes.LooseSecret, boolPointer(false))
}

func (c *config) normalizeLegacySanitization() {
	if len(c.Sanitization.ReplacementGroups) != 0 || len(c.Sanitization.Replacements) == 0 {
		return
	}
	for index, rule := range c.Sanitization.Replacements {
		order := index
		c.Sanitization.ReplacementGroups = append(c.Sanitization.ReplacementGroups, replacementGroup{
			Models: rule.Models, BaseURLs: rule.BaseURLs, SourceFormats: rule.SourceFormats, ToFormats: rule.ToFormats,
			Replacements: []replacement{{ID: rule.ID, Src: rule.Src, Dst: rule.Dst, Order: &order}},
		})
	}
}

func (c *piiConfig) mergeMissing(source piiConfig) {
	merge := func(target **bool, value *bool) {
		if *target == nil && value != nil {
			*target = boolPointer(boolValue(value))
		}
	}
	merge(&c.Gitleaks, source.Gitleaks)
	merge(&c.Email, source.Email)
	merge(&c.Phone, source.Phone)
	merge(&c.NationalID, source.NationalID)
	merge(&c.BankCard, source.BankCard)
	merge(&c.IP, source.IP)
	merge(&c.JWT, source.JWT)
	merge(&c.UUID, source.UUID)
	merge(&c.CredentialURL, source.CredentialURL)
	merge(&c.MACAddress, source.MACAddress)
	merge(&c.IPv6, source.IPv6)
	merge(&c.Path, source.Path)
	merge(&c.GenericToken, source.GenericToken)
}

func (c config) migrationWarnings() []string {
	var warnings []string
	for _, group := range c.Sanitization.ReplacementGroups {
		if len(group.BaseURLs) != 0 {
			warnings = append(warnings, "sanitization group "+displayGroupID(group)+" contains legacy base_urls; migrate it to CPA to_formats")
		}
	}
	sort.Strings(warnings)
	return warnings
}

func displayGroupID(group replacementGroup) string {
	if strings.TrimSpace(group.ID) != "" {
		return strings.TrimSpace(group.ID)
	}
	return "<unnamed>"
}

func boolPointer(value bool) *bool { return &value }
func boolValue(value *bool) bool   { return value != nil && *value }

func fillBool(target **bool, fallback *bool) {
	if *target == nil {
		value := boolValue(fallback)
		*target = &value
	}
}
