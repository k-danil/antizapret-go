package utils

import "testing"

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		// подчёркивания в лейблах сохраняются (не строгий STD3) — регресс-гард
		"_dmarc.example.com": "_dmarc.example.com",
		"a_1.bxfilm10.art":   "a_1.bxfilm10.art",
		// IDN всё ещё конвертится в punycode мягким профилем
		"президент.рф":              "xn--d1abbgf6aiiy.xn--p1ai",
		"xn--d1abbgf6aiiy.xn--p1ai": "xn--d1abbgf6aiiy.xn--p1ai",
		// канонизация: регистр + хвостовая точка + кавычки/пробелы
		"Example.COM.":  "example.com",
		" \"quoted.com": "quoted.com",
		// мусор → пусто
		"":    "",
		"...": "",
	}
	for in, want := range cases {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
