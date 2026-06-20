package router

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlainParserLongLineDoesNotAbort(t *testing.T) {
	long := strings.Repeat("a", 70*1024) // > 64 КБ — дефолтный лимит bufio.Scanner

	var got []string
	err := PlainParser{subdomains: true}.Parse(
		strings.NewReader(long+"\ngood.com\n"),
		func(e Entry) { got = append(got, e.Domain) },
	)
	require.NoError(t, err, "длинная строка не должна обрывать скан")
	require.Contains(t, got, "good.com", "строка после длинной не должна теряться")
}
