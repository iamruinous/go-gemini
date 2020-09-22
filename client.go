package gemini

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"strconv"
	"strings"
)

// Client is a Gemini client.
type Client struct{}

// Request makes a request for the provided URL. The host is inferred from the URL.
func (c *Client) Request(url string) (*Response, error) {
	if len(url) > 1024 {
		return nil, ErrInvalidURL
	}

	req, err := NewRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// ProxyRequest requests the provided URL from the provided host.
func (c *Client) ProxyRequest(host, url string) (*Response, error) {
	if len(url) > 1024 {
		return nil, ErrInvalidURL
	}

	req, err := NewProxyRequest(host, url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Do sends a Gemini request and returns a Gemini response.
func (c *Client) Do(req *Request) (*Response, error) {
	host := req.Host
	if strings.LastIndex(host, ":") == -1 {
		// The default port is 1965
		host += ":1965"
	}

	// Allow self signed certificates
	config := tls.Config{}
	config.InsecureSkipVerify = true
	config.Certificates = req.Certificates

	conn, err := tls.Dial("tcp", host, &config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Write the request
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	// Read the response
	b, err := ioutil.ReadAll(conn)
	if err != nil {
		return nil, err
	}

	// Ensure that the response is long enough
	// The minimum response: <STATUS><SPACE><CR><LF> (5 bytes)
	if len(b) < 5 {
		return nil, ErrProtocol
	}

	// Parse the response header
	status, err := strconv.Atoi(string(b[:2]))
	if err != nil {
		return nil, err
	}

	// Read one space
	if b[2] != ' ' {
		return nil, ErrProtocol
	}

	// Find the first <CR><LF>
	i := bytes.Index(b, []byte("\r\n"))
	if i < 3 {
		return nil, ErrProtocol
	}

	// Read the meta
	meta := string(b[3:i])
	if len(meta) > 1024 {
		return nil, ErrProtocol
	}

	// Read the response body
	body := b[i+2:]

	return &Response{
		Status: status,
		Meta:   meta,
		Body:   body,
	}, nil
}
