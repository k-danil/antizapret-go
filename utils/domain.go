package utils

import (
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// StrictDomainName(false) строго после MapForLookup (тот включает STD3) — иначе '_' в не-ASCII именах режется
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
		// ASCII мимо IDNA намеренно: checkHyphens отбросил бы реальные имена (r3---sn-….googlevideo.com),
		// а битая xn--метка просто не совпадёт
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
