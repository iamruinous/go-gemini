package gemini

// Status codes.
type Status int

const (
	StatusInput                    Status = 10
	StatusSensitiveInput           Status = 11
	StatusSuccess                  Status = 20
	StatusRedirect                 Status = 30
	StatusRedirectPermanent        Status = 31
	StatusTemporaryFailure         Status = 40
	StatusServerUnavailable        Status = 41
	StatusCGIError                 Status = 42
	StatusProxyError               Status = 43
	StatusSlowDown                 Status = 44
	StatusPermanentFailure         Status = 50
	StatusNotFound                 Status = 51
	StatusGone                     Status = 52
	StatusProxyRequestRefused      Status = 53
	StatusBadRequest               Status = 59
	StatusCertificateRequired      Status = 60
	StatusCertificateNotAuthorized Status = 61
	StatusCertificateNotValid      Status = 62
)

// Status code categories.
type StatusClass int

const (
	StatusClassInput               StatusClass = 1
	StatusClassSuccess             StatusClass = 2
	StatusClassRedirect            StatusClass = 3
	StatusClassTemporaryFailure    StatusClass = 4
	StatusClassPermanentFailure    StatusClass = 5
	StatusClassCertificateRequired StatusClass = 6
)

// Class returns the status class for this status code.
func (s Status) Class() StatusClass {
	return StatusClass(s / 10)
}

// Message returns a status message corresponding to this status code.
func (s Status) Message() string {
	switch s {
	case StatusInput:
		return "Input"
	case StatusSensitiveInput:
		return "Sensitive input"
	case StatusSuccess:
		return "Success"
	case StatusRedirect:
		return "Redirect"
	case StatusRedirectPermanent:
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
