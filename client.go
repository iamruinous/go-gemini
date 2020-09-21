package gemini

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrProtocol = errors.New("Protocol error")
)

// Client is a Gemini client.
type Client struct {
	TLSConfig *tls.Config // TODO: Client certificate support
}

// Request makes a request for the provided URL. The host is inferred from the URL.
func (c *Client) Request(url string) (*Response, error) {
	req, err := NewRequest(url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// ProxyRequest requests the provided URL from the provided host.
func (c *Client) ProxyRequest(host, url string) (*Response, error) {
	req, err := NewProxyRequest(host, url)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Request is a Gemini request.
type Request struct {
	Host string   // host or host:port
	URL  *url.URL // The URL to request
}

// NewRequest returns a new request. The host is inferred from the provided url.
func NewRequest(rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// Ignore UserInfo if present
	u.User = nil

	return &Request{
		Host: u.Host,
		URL:  u,
	}, nil
}

// NewProxyRequest makes a new request using the provided host.
func NewProxyRequest(host, rawurl string) (*Request, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}

	// Ignore UserInfo if present
	u.User = nil

	return &Request{
		Host: host,
		URL:  u,
	}, nil
}

// Do sends a Gemini request and returns a Gemini response.
func (c *Client) Do(req *Request) (*Response, error) {
	host := req.Host
	if strings.LastIndex(host, ":") == -1 {
		// The default port is 1965
		host += ":1965"
	}

	config := &tls.Config{
		// Allow self-signed certificates
		// TODO: Trust on first use
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", host, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Write the request
	request := req.URL.String() + "\r\n"
	if _, err := conn.Write([]byte(request)); err != nil {
		return nil, err
	}

	buf := bufio.NewReader(conn)

	// Read the response header
	code := make([]byte, 2)
	if _, err := buf.Read(code); err != nil {
		return nil, err
	}
	status, err := strconv.Atoi(string(code))
	if err != nil {
		return nil, err
	}

	// Read one space
	if space, err := buf.ReadByte(); err != nil {
		return nil, err
	} else if space != ' ' {
		return nil, ErrProtocol
	}

	// Read the meta
	meta, err := readLine(buf)
	if err != nil {
		return nil, err
	}

	// Read the response body
	body, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	return &Response{
		Status: status,
		Meta:   meta,
		Body:   body,
	}, nil
}
