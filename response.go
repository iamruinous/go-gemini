package gemini

import (
	"bufio"
	"crypto/tls"
	"io"
	"strconv"
)

// Response is a Gemini response.
type Response struct {
	// Status contains the response status code.
	Status Status

	// Meta contains more information related to the response status.
	// For successful responses, Meta should contain the mimetype of the response.
	// For failure responses, Meta should contain a short description of the failure.
	// Meta should not be longer than 1024 bytes.
	Meta string

	// Body contains the response body for successful responses.
	Body io.ReadCloser

	// Request is the request that was sent to obtain this response.
	Request *Request

	// TLS contains information about the TLS connection on which the response
	// was received.
	TLS tls.ConnectionState
}

// read reads a Gemini response from the provided io.ReadCloser.
func (resp *Response) read(rc io.ReadCloser) error {
	br := bufio.NewReader(rc)
	// Read the status
	statusB := make([]byte, 2)
	if _, err := br.Read(statusB); err != nil {
		return err
	}
	status, err := strconv.Atoi(string(statusB))
	if err != nil {
		return err
	}
	resp.Status = Status(status)

	// Disregard invalid status codes
	const minStatus, maxStatus = 1, 6
	statusClass := resp.Status.Class()
	if statusClass < minStatus || statusClass > maxStatus {
		return ErrInvalidResponse
	}

	// Read one space
	if b, err := br.ReadByte(); err != nil {
		return err
	} else if b != ' ' {
		return ErrInvalidResponse
	}

	// Read the meta
	meta, err := br.ReadString('\r')
	if err != nil {
		return err
	}
	// Trim carriage return
	meta = meta[:len(meta)-1]
	// Ensure meta is less than or equal to 1024 bytes
	if len(meta) > 1024 {
		return ErrInvalidResponse
	}
	// Default mime type of text/gemini; charset=utf-8
	if statusClass == StatusClassSuccess && meta == "" {
		meta = "text/gemini; charset=utf-8"
	}
	resp.Meta = meta

	// Read terminating newline
	if b, err := br.ReadByte(); err != nil {
		return err
	} else if b != '\n' {
		return ErrInvalidResponse
	}

	if resp.Status.Class() == StatusClassSuccess {
		resp.Body = newReadCloserBody(br, rc)
	}
	return nil
}

type readCloserBody struct {
	br *bufio.Reader // used until empty
	io.ReadCloser
}

func newReadCloserBody(br *bufio.Reader, rc io.ReadCloser) io.ReadCloser {
	body := &readCloserBody{ReadCloser: rc}
	if br.Buffered() != 0 {
		body.br = br
	}
	return body
}

func (b *readCloserBody) Read(p []byte) (n int, err error) {
	if b.br != nil {
		if n := b.br.Buffered(); len(p) > n {
			p = p[:n]
		}
		n, err = b.br.Read(p)
		if b.br.Buffered() == 0 {
			b.br = nil
		}
		return n, err
	}
	return b.ReadCloser.Read(p)
}
