/*
Package gemini implements the Gemini protocol.

Get makes a Gemini request:

	resp, err := gemini.Get("gemini://example.com")
	if err != nil {
		// handle error
	}
	// ...

The client must close the response body when finished with it:

	resp, err := gemini.Get("gemini://example.com")
	if err != nil {
		// handle error
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	// ...

For control over client behavior, create a Client:

	var client gemini.Client
	resp, err := client.Get("gemini://example.com")
	if err != nil {
		// handle error
	}
	// ...

Clients can load their own list of known hosts:

	err := client.KnownHosts.Load("path/to/my/known_hosts")
	if err != nil {
		// handle error
	}

Clients can control when to trust certificates with TrustCertificate:

	client.TrustCertificate = func(hostname string, cert *x509.Certificate, knownHosts *gemini.KnownHosts) error {
		return knownHosts.Lookup(hostname, cert)
	}

Clients can create client certificates upon the request of a server:

	client.CreateCertificate = func(hostname, path string) *tls.Certificate {
		return gemini.CreateCertificate(gemini.CertificateOptions{
			Duration: time.Hour,
		})
	}

Server is a Gemini server.

	var server gemini.Server

Servers must be configured with certificates:

	err := server.Certificates.Load("/var/lib/gemini/certs")
	if err != nil {
		// handle error
	}

Servers can accept requests for multiple hosts and schemes:

	server.RegisterFunc("example.com", func(w *gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "Welcome to example.com")
	})
	server.RegisterFunc("example.org", func(w *gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "Welcome to example.org")
	})
	server.RegisterFunc("http://example.net", func(w *gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "Proxied content from http://example.net")
	})

To start the server, call ListenAndServe:

	err := server.ListenAndServe()
	if err != nil {
		// handle error
	}
*/
package gemini
