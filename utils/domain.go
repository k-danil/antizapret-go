package utils

import (
	"strings"

	"golang.org/x/net/idna"
)

func NormalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'")
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	s = strings.TrimRight(s, ".")
	if s == "" {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil || ascii == "" {
		return ""
	}
	return ascii
}

func DomainToUnicode(s string) string {
	ascii, err := idna.Lookup.ToUnicode(s)
	if err != nil || ascii == "" {
		return ""
	}
	return ascii
}
