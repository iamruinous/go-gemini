/*
Package gemini implements the Gemini protocol.

Get makes a Gemini request:

	resp, err := gemini.Get("gemini://example.com")
	if err != nil {
		// handle error
	}
	defer resp.Body.Close()
	// ...

For control over client behavior, create a Client:

	client := &gemini.Client{}
	resp, err := client.Get("gemini://example.com")
	if err != nil {
		// handle error
	}
	// ...

Server is a Gemini server.

	server := &gemini.Server{
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
	}

Servers should be configured with certificates:

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
