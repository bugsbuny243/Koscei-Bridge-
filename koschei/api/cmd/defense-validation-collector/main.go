package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"koschei/api/internal/defensecollector"
)

const maxCollectorRequestBytes = 4 << 20
const collectorPrivateKeyEnvironment = "KOSCHEI_DEFENSE_COLLECTOR_ED25519_PRIVATE_KEY"

func main() {
	privateKey, err := collectorPrivateKeyFromEnvironment()
	if err == nil {
		err = run(os.Stdin, os.Stdout, privateKey)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "defense validation collector:", err)
		os.Exit(1)
	}
}

func run(input io.Reader, output io.Writer, privateKey ed25519.PrivateKey) error {
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

	result, err := defensecollector.CollectV03(request, privateKey)
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

func collectorPrivateKeyFromEnvironment() (ed25519.PrivateKey, error) {
	encoded := os.Getenv(collectorPrivateKeyEnvironment)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("%s must contain a canonical base64url Ed25519 private key", collectorPrivateKeyEnvironment)
	}
	return ed25519.PrivateKey(decoded), nil
}
