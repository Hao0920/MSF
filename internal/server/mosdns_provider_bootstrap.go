package server

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// providerBootstrapValuesFromMihomoConfig extracts exact host rules for HTTP
// proxy-providers. URL credentials, paths, queries and fragments are discarded.
func providerBootstrapValuesFromMihomoConfig(content string) ([]string, error) {
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, fmt.Errorf("parse Mihomo proxy providers: %w", err)
	}
	if cfg == nil {
		return nil, nil
	}
	providers := normalizeConfigProviders(cfg["proxy-providers"])
	hosts := make(map[string]struct{}, len(providers))
	for name, provider := range providers {
		if name == "msf_manual" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(stringMapValue(provider, "type")))
		if kind != "" && kind != "http" {
			continue
		}
		raw := strings.TrimSpace(stringMapValue(provider, "url"))
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(u.Hostname())), ".")
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		hosts["full:"+host] = struct{}{}
	}
	values := make([]string, 0, len(hosts))
	for value := range hosts {
		values = append(values, value)
	}
	sort.Strings(values)
	return values, nil
}

func providerBootstrapFileContent(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, "\n") + "\n"
}
