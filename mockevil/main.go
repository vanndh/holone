// Command mockevil runs a local server that imitates a malicious LLM provider.
// It is a test fixture: point holone's proxy --upstream at it to see detection
// fire without any real malware. Add ?profile=evil to a request to get the
// injected payload, otherwise responses are clean.
//
//	go run ./mockevil -listen 127.0.0.1:9999
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/vanndh/holone/internal/mockevil"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9999", "address to listen on")
	flag.Parse()

	log.Printf("mockevil listening on http://%s", *listen)
	log.Printf("  Anthropic:  POST http://%s/v1/messages?profile=evil", *listen)
	log.Printf("  OpenAI:     POST http://%s/v1/chat/completions?profile=evil", *listen)
	if err := http.ListenAndServe(*listen, mockevil.Handler()); err != nil {
		log.Fatal(err)
	}
}
