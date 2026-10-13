package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		// '_' в не-ASCII имени: StrictDomainName(false) обязан стоять после MapForLookup
		"_dmarc.президент.рф": "_dmarc.xn--d1abbgf6aiiy.xn--p1ai",
		// ASCII мимо IDNA: checkHyphens отбросил бы это имя
		"r3---sn-x.googlevideo.com": "r3---sn-x.googlevideo.com",
	}
	for in, want := range cases {
		assert.Equalf(t, want, NormalizeDomain(in), "NormalizeDomain(%q)", in)
	}
}
