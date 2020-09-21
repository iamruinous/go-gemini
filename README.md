# go-gemini

`go-gemini` implements the [Gemini protocol](https://gemini.circumlunar.space) in
Go.

It aims to provide an interface similar to that of `net/http` to make it easy
to develop Gemini clients and servers.

## Usage

First generate TLS keys for your server to use.

```sh
openssl genrsa -out server.key 2048
openssl ecparam -genkey -name secp384r1 -out server.key
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

Next, import and use `go-gemini`. Here is a simple server:

```go
import (
	"git.sr.ht/~adnano/go-gemini"
)

func main() {
	config := &tls.Config{}
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	config.Certificates = append(config.Certificates, cert)

	mux := &gemini.Mux{}
	mux.HandleFunc("/", func(url *url.URL) *gemini.Response {
		return &gemini.Response{
			Status: gemini.StatusSuccess,
			Meta:   "text/gemini",
			Body:   []byte("You requested " + url.String()),
		}
	})

	server := gemini.Server{
		TLSConfig: config,
		Handler:   mux,
	}
	server.ListenAndServe()
}
```

And a simple client:

```go
import (
	"git.sr.ht/~adnano/go-gemini"
)

var client gemini.Client

func makeRequest(url string) {
	resp, err := client.Get(url)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Status code:", resp.Status)
	fmt.Println("Meta:", resp.Meta)

	switch resp.Status / 10 {
	case gemini.StatusClassInput:
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Printf("%s: ", resp.Meta)
		scanner.Scan()
		query := scanner.Text()
		makeRequest(url + "?" + query)
		return
	case gemini.StatusClassSuccess:
		fmt.Print("Body:\n", string(resp.Body))
	case gemini.StatusClassRedirect:
		log.Print("Redirecting to ", resp.Meta)
		makeRequest(resp.Meta)
		return
	case gemini.StatusClassTemporaryFailure:
		log.Fatal("Temporary failure")
	case gemini.StatusClassPermanentFailure:
		log.Fatal("Permanent failure")
	case gemini.StatusClassClientCertificateRequired:
		log.Fatal("Client certificate required")
	default:
		log.Fatal("Protocol error: invalid status code")
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s gemini://...", os.Args[0])
	}
	makeRequest(os.Args[1])
}
```
