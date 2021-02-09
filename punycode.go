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

// punycodeHost returns the punycoded version of host.
// host may contain a port.
func punycodeHost(host string) (string, error) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
		port = ""
	}
	hostname, err = punycodeHostname(hostname)
	if err != nil {
		return "", err
	}
	if port == "" {
		return hostname, nil
	}
	return net.JoinHostPort(hostname, port), nil
}
