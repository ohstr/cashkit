// Command export-vectors writes cashkit's conformance vectors (design §11.1).
//
// Every expected value is computed by calling nmilat, the Go SDK cashkit
// ports, on a fixed set of inputs. Nothing here re-implements protocol logic:
// if nmilat changes behaviour, `just vectors` changes the JSON and CI's drift
// check turns red until the TypeScript port follows.
//
// Inputs are deterministic (fixed keys, deterministic RFC 6979 signatures, no
// random nonces), so regenerating never produces a diff by itself.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
)

type vectorFile struct {
	name  string
	build func() (any, error)
}

var files = []vectorFile{
	{"tlv.json", buildTLV},
	{"hub-group.json", buildHubGroup},
	{"cash-string.json", buildCashString},
	{"provenance.json", buildProvenance},
	{"connection-key.json", buildConnectionKey},
	{"nip44.json", buildNIP44},
	{"nip01.json", buildNIP01},
	{"bolt11.json", buildBolt11},
	{"claim.json", buildClaim},
	{"nip19.json", buildNIP19},
	{"nip47.json", buildNIP47},
	{"nip04.json", buildNIP04},
	{"nipcw.json", buildNIPCW},
	{"reply-key.json", buildReplyKey},
	{"canonical-params.json", buildCanonicalParams},
	{"padding.json", buildPadding},
	{"envelope.json", buildEnvelope},
	{"proof.json", buildProofVectors},
	{"announcement.json", buildAnnouncement},
}

// header opens every vector file so a reader can tell where it came from.
type header struct {
	Description string `json:"description"`
	Source      string `json:"source"`
	Nmilat      string `json:"nmilat"`
}

func newHeader(description, source string) header {
	return header{Description: description, Source: source, Nmilat: nmilatVersion()}
}

func nmilatVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/ohstr/nmilat" {
			if dep.Replace != nil {
				return dep.Replace.Version
			}
			return dep.Version
		}
	}
	return "unknown"
}

func main() {
	out := flag.String("out", "vectors", "directory to write the vector files into")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail(err)
	}
	for _, f := range files {
		v, err := f.build()
		if err != nil {
			fail(fmt.Errorf("%s: %w", f.name, err))
		}
		data, err := marshal(v)
		if err != nil {
			fail(fmt.Errorf("%s: %w", f.name, err))
		}
		if err := os.WriteFile(filepath.Join(*out, f.name), data, 0o644); err != nil {
			fail(err)
		}
	}
}

// marshal is json.MarshalIndent without HTML escaping, so strings such as
// "a<b" stay readable, plus a trailing newline.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "export-vectors:", err)
	os.Exit(1)
}

// errString is the error text a failed call produced, or "" on success. It
// is recorded for humans; the TypeScript port only has to fail, not match it.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func repeat(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func strPtr(s string) *string { return &s }
