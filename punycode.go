package gemini

import (
	"net"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// punycodeHostname returns the punycoded version of hostname.
func punycodeHostname(hostname string) (string, error) {
	if net.ParseIP(hostname) != nil {
		return hostname, nil
	}
	if isASCII(hostname) {
		return hostname, nil
	}
	return idna.Lookup.ToASCII(hostname)
}
