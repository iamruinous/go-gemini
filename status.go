package gemini

// Gemini status codes.
const (
	StatusInput                    = 10
	StatusSensitiveInput           = 11
	StatusSuccess                  = 20
	StatusRedirect                 = 30
	StatusPermanentRedirect        = 31
	StatusTemporaryFailure         = 40
	StatusServerUnavailable        = 41
	StatusCGIError                 = 42
	StatusProxyError               = 43
	StatusSlowDown                 = 44
	StatusPermanentFailure         = 50
	StatusNotFound                 = 51
	StatusGone                     = 52
	StatusProxyRequestRefused      = 53
	StatusBadRequest               = 59
	StatusCertificateRequired      = 60
	StatusCertificateNotAuthorized = 61
	StatusCertificateNotValid      = 62
)

// StatusClass returns the status class for the provided status code.
// 1x becomes 10, 2x becomes 20, and so on.
func StatusClass(code int) int {
	return (code / 10) * 10
}

// StatusText returns a text for the provided status code.
// It returns the empty string if the status code is unknown.
func StatusText(code int) string {
	switch code {
	case StatusInput:
		return "Input"
	case StatusSensitiveInput:
		return "Sensitive input"
	case StatusSuccess:
		return "Success"
	case StatusRedirect:
		return "Redirect"
	case StatusPermanentRedirect:
		return "Permanent redirect"
	case StatusTemporaryFailure:
		return "Temporary failure"
	case StatusServerUnavailable:
		return "Server unavailable"
	case StatusCGIError:
		return "CGI error"
	case StatusProxyError:
		return "Proxy error"
	case StatusSlowDown:
		return "Slow down"
	case StatusPermanentFailure:
		return "Permanent failure"
	case StatusNotFound:
		return "Not found"
	case StatusGone:
		return "Gone"
	case StatusProxyRequestRefused:
		return "Proxy request refused"
	case StatusBadRequest:
		return "Bad request"
	case StatusCertificateRequired:
		return "Certificate required"
	case StatusCertificateNotAuthorized:
		return "Certificate not authorized"
	case StatusCertificateNotValid:
		return "Certificate not valid"
	}
	return ""
}
