package gemini

import (
	"bufio"
	"crypto/tls"
	"io/ioutil"
	"strconv"
)

// Response is a Gemini response.
type Response struct {
	// Status represents the response status.
	Status Status

	// Meta contains more information related to the response status.
	// For successful responses, Meta should contain the mimetype of the response.
	// For failure responses, Meta should contain a short description of the failure.
	// Meta should not be longer than 1024 bytes.
	Meta string

	// Body contains the response body.
	Body []byte

	// TLS contains information about the TLS connection on which the response
	// was received.
	TLS tls.ConnectionState
}

// read reads a Gemini response from the provided buffered reader.
func (resp *Response) read(r *bufio.Reader) error {
	// Read the status
	statusB := make([]byte, 2)
	if _, err := r.Read(statusB); err != nil {
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
	if b, err := r.ReadByte(); err != nil {
		return err
	} else if b != ' ' {
		return ErrInvalidResponse
	}

	// Read the meta
	meta, err := r.ReadString('\r')
	if err != nil {
		return err
	}
	// Trim carriage return
	meta = meta[:len(meta)-1]
	// Ensure meta is less than or equal to 1024 bytes
	if len(meta) > 1024 {
		return ErrInvalidResponse
	}
	resp.Meta = meta

	// Read terminating newline
	if b, err := r.ReadByte(); err != nil {
		return err
	} else if b != '\n' {
		return ErrInvalidResponse
	}

	// Read response body
	if resp.Status.Class() == StatusClassSuccess {
		var err error
		resp.Body, err = ioutil.ReadAll(r)
		if err != nil {
			return err
		}
	}
	return nil
}
