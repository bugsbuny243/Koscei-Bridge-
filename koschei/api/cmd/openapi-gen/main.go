package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	koscheiopenapi "koschei/api/internal/openapi"
)

func main() {
	sourceDir := flag.String("source", filepath.FromSlash("internal/http"), "registered HTTP route source directory")
	output := flag.String("output", "openapi.yaml", "OpenAPI 3.1 output file")
	check := flag.Bool("check", false, "fail if the generated document differs from the committed file")
	flag.Parse()

	generated, routes, err := koscheiopenapi.Generate(*sourceDir)
	if err != nil {
		fatal(err)
	}
	if *check {
		committed, err := os.ReadFile(*output)
		if err != nil {
			fatal(err)
		}
		if string(committed) != string(generated) {
			fatal(fmt.Errorf("%s is stale; run go run ./cmd/openapi-gen", *output))
		}
		fmt.Printf("OpenAPI drift check passed: %d registered API paths\n", len(routes))
		return
	}
	if err := os.WriteFile(*output, generated, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("Wrote %s with %d registered API paths\n", *output, len(routes))
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
