/*
Package gmi implements the Gemini protocol.

Send makes a Gemini request:

	req := gmi.NewRequest("gemini://example.com")
	resp, err := gmi.Send(req)
	if err != nil {
		// handle error
	}
	// ...

For control over client behavior, create a Client:

	var client gmi.Client
	err := client.Send(req)
	if err != nil {
		// handle error
	}

The default client loads known hosts from "$XDG_DATA_HOME/gemini/known_hosts".
Custom clients can load their own list of known hosts:

	err := client.KnownHosts.LoadFrom("path/to/my/known_hosts")
	if err != nil {
		// handle error
	}

Clients can control when to trust certificates with TrustCertificate:

	client.TrustCertificate = func(hostname string, cert *x509.Certificate, knownHosts *gmi.KnownHosts) error {
		return knownHosts.Lookup(hostname, cert)
	}

If a server responds with StatusCertificateRequired, the default client will generate a certificate and resend the request with it. Custom clients can do so in GetCertificate:

	client.GetCertificate = func(hostname string, store *gmi.CertificateStore) *tls.Certificate {
		// If the certificate is in the store, return it
		if cert, err := store.Lookup(hostname); err == nil {
			return &cert
		}
		// Otherwise, generate a certificate
		duration := time.Hour
		cert, err := gmi.NewCertificate(hostname, duration)
		if err != nil {
			return nil
		}
		// Store and return the certificate
		store.Add(hostname, cert)
		return &cert
	}

Server is a Gemini server.

	var server gmi.Server

Servers must be configured with certificates:

	var server gmi.Server
	server.CertificateStore.Load("/var/lib/gemini/certs")

Servers can accept requests for multiple hosts and schemes:

	server.HandleFunc("example.com", func(rw *gmi.ResponseWriter, req *gmi.Request) {
		fmt.Fprint(rw, "Welcome to example.com")
	})
	server.HandleFunc("example.org", func(rw *gmi.ResponseWriter, req *gmi.Request) {
		fmt.Fprint(rw, "Welcome to example.org")
	})
	server.HandleSchemeFunc("http", "example.net", func(rw *gmi.ResponseWriter, req *gmi.Request) {
		fmt.Fprint(rw, "Proxied content from example.net")
	})

To start the server, call ListenAndServe:

	err := server.ListenAndServe()
	if err != nil {
		// handle error
	}
*/
package gmi
