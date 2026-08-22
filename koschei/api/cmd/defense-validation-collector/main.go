package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"koschei/api/internal/defensecollector"
)

const maxCollectorRequestBytes = 4 << 20

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "defense validation collector:", err)
		os.Exit(1)
	}
}

func run(input io.Reader, output io.Writer) error {
	limited := &io.LimitedReader{R: input, N: maxCollectorRequestBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()

	var request defensecollector.RequestV03
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if limited.N <= 0 {
		return errors.New("request exceeds size limit")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("request must contain exactly one JSON value")
		}
		return fmt.Errorf("decode trailing request data: %w", err)
	}

	result, err := defensecollector.CollectV03(request)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}
