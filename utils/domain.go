package utils

import (
	"strings"

	"golang.org/x/net/idna"
)

// idna.Lookup, но с разрешёнными '_' в лейблах: подчёркивания валидны в DNS
// (_dmarc, _mta-sts, SRV-записи, реальные поддомены), а строгий STD3 их режет.
var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
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
	ascii, err := lookupProfile.ToASCII(s)
	if err != nil || ascii == "" {
		return ""
	}
	return ascii
}
