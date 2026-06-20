package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		// подчёркивания в лейблах сохраняются (не строгий STD3) — регресс-гард
		"_dmarc.example.com": "_dmarc.example.com",
		"a_1.bxfilm10.art":   "a_1.bxfilm10.art",
		// IDN всё ещё конвертится в punycode мягким профилем
		"президент.рф":              "xn--d1abbgf6aiiy.xn--p1ai",
		"xn--d1abbgf6aiiy.xn--p1ai": "xn--d1abbgf6aiiy.xn--p1ai",
		"Example.COM.":              "example.com",
		" \"quoted.com":             "quoted.com",
		"":                          "",
		"...":                       "",
	}
	for in, want := range cases {
		assert.Equalf(t, want, NormalizeDomain(in), "NormalizeDomain(%q)", in)
	}
}

func BenchmarkNormalizeDomainASCII(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		NormalizeDomain("www.example.com")
	}
}

func BenchmarkNormalizeDomainIDN(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		NormalizeDomain("президент.рф")
	}
}
