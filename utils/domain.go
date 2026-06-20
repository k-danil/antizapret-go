package utils

import (
	"strings"
	"unicode/utf8"

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
	if isASCII(s) {
		// чистый ASCII совпадает с выводом ToASCII — IDNA-преобразование пропускаем
		return s
	}
	ascii, err := lookupProfile.ToASCII(s)
	if err != nil || ascii == "" {
		return ""
	}
	return ascii
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
