/*
Package gemini provides Gemini client and server implementations.

Client is a Gemini client.

	client := &gemini.Client{}
	resp, err := client.Get("gemini://example.com")
	if err != nil {
		// handle error
	}
	defer resp.Body.Close()
	// ...

Server is a Gemini server.

	server := &gemini.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

Servers should be configured with certificates:

	err := server.Certificates.Load("/var/lib/gemini/certs")
	if err != nil {
		// handle error
	}

ServeMux is a Gemini request multiplexer.
ServeMux can handle requests for multiple hosts and schemes.

	mux := &gemini.ServeMux{}
	mux.HandleFunc("example.com", func(w gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "Welcome to example.com")
	})
	mux.HandleFunc("example.org/about.gmi", func(w gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "About example.org")
	})
	mux.HandleFunc("http://example.net", func(w gemini.ResponseWriter, r *gemini.Request) {
		fmt.Fprint(w, "Proxied content from http://example.net")
	})
	server.Handler = mux

To start the server, call ListenAndServe:

	err := server.ListenAndServe()
	if err != nil {
		// handle error
	}
*/
package gemini
