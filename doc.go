/*
Package gemini implements the Gemini protocol.

Send makes a Gemini request with the default client:

	req := gemini.NewRequest("gemini://example.com")
	resp, err := gemini.Send(req)
	if err != nil {
		// handle error
	}
	// ...

For control over client behavior, create a custom Client:

	var client gemini.Client
	resp, err := client.Send(req)
	if err != nil {
		// handle error
	}
	// ...

The default client loads known hosts from "$XDG_DATA_HOME/gemini/known_hosts".
Custom clients can load their own list of known hosts:

	err := client.KnownHosts.Load("path/to/my/known_hosts")
	if err != nil {
		// handle error
	}

Clients can control when to trust certificates with TrustCertificate:

	client.TrustCertificate = func(hostname string, cert *x509.Certificate, knownHosts *gemini.KnownHosts) error {
		return knownHosts.Lookup(hostname, cert)
	}

If a server responds with StatusCertificateRequired, the default client will generate a certificate and resend the request with it. Custom clients can do so in GetCertificate:

	client.GetCertificate = func(hostname string, store *gemini.CertificateStore) *tls.Certificate {
		// If the certificate is in the store, return it
		if cert, err := store.Lookup(hostname); err == nil {
			return &cert
		}
		// Otherwise, generate a certificate
		duration := time.Hour
		cert, err := gemini.NewCertificate(hostname, duration)
		if err != nil {
			return nil
		}
		// Store and return the certificate
		store.Add(hostname, cert)
		return &cert
	}

Server is a Gemini server.

	var server gemini.Server

Servers must be configured with certificates:

	err := server.CertificateStore.Load("/var/lib/gemini/certs")
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
