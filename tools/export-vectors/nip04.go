package main

import (
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nip04"
	"github.com/ohstr/nmilat/utils"
)

// NIP-04 (legacy AES-256-CBC), for NWC wallets that speak only nip04
// (design §2.3). The IV comes from crypto/rand, seeded so the file is
// reproducible.

type nip04Case struct {
	Name           string `json:"name"`
	SenderSecret   string `json:"senderSecret"`
	ReceiverPubkey string `json:"receiverPubkey"`
	ReceiverSecret string `json:"receiverSecret"`
	SenderPubkey   string `json:"senderPubkey"`
	Plaintext      string `json:"plaintext"`
	Payload        string `json:"payload"`
}

type nip04Invalid struct {
	Name    string `json:"name"`
	Payload string `json:"payload"`
	// What nmilat's nip04.Decrypt does with it: "refused" or "accepted".
	Nmilat string `json:"nmilat"`
}

type nip04File struct {
	header
	Valid   []nip04Case    `json:"valid"`
	Invalid []nip04Invalid `json:"invalid"`
}

const (
	nip04SenderSecret   = "0000000000000000000000000000000000000000000000000000000000000001"
	nip04ReceiverSecret = "0000000000000000000000000000000000000000000000000000000000000002"
)

// nip04Refuses reports whether f fails, by error or otherwise.
func nip04Refuses(f func() (string, error)) (refused bool) {
	defer func() {
		if recover() != nil {
			refused = true
		}
	}()
	_, err := f()
	return err != nil
}

func buildNIP04() (any, error) {
	f := nip04File{header: newHeader(
		"NIP-04 encrypt/decrypt as nmilat does it: AES-256-CBC over the shared x-coordinate, PKCS#7, base64 ciphertext ?iv= base64 IV.",
		"nip04/nip04.go",
	)}
	senderPub, err := utils.GetPublicKey(nip04SenderSecret)
	if err != nil {
		return nil, err
	}
	receiverPub, err := utils.GetPublicKey(nip04ReceiverSecret)
	if err != nil {
		return nil, err
	}
	plaintexts := []struct{ name, text string }{
		{"short", "hello"},
		{"15 bytes", "0123456789abcde"},
		{"16 bytes (a full block of padding)", "0123456789abcdef"},
		{"unicode", "ünïcødé 🔑"},
		{"nwc request", `{"method":"make_invoice","params":{"amount":21000}}`},
		{"empty", ""},
	}
	for i, p := range plaintexts {
		payload := withSeededRand(fmt.Sprintf("nip04-%d", i), func() string {
			s, err := nip04.Encrypt(p.text, nip04SenderSecret, receiverPub)
			if err != nil {
				panic(err)
			}
			return s
		})
		back, err := nip04.Decrypt(payload, senderPub, nip04ReceiverSecret)
		if err != nil || back != p.text {
			return nil, fmt.Errorf("nip04 %s: round trip failed: %v", p.name, err)
		}
		f.Valid = append(f.Valid, nip04Case{p.name, nip04SenderSecret, receiverPub, nip04ReceiverSecret, senderPub, p.text, payload})
	}
	good := f.Valid[0].Payload
	invalid := []struct{ name, payload string }{
		{"no ?iv= separator", "AAAAAAAAAAAAAAAAAAAAAA=="},
		{"IV not 16 bytes", "AAAAAAAAAAAAAAAAAAAAAA==?iv=AAAA"},
		{"ciphertext not base64", "!!!?iv=AAAAAAAAAAAAAAAAAAAAAA=="},
		{"ciphertext not a whole number of blocks", "AAAAAAAA?iv=AAAAAAAAAAAAAAAAAAAAAA=="},
		{"empty ciphertext", "?iv=AAAAAAAAAAAAAAAAAAAAAA=="},
		{"wrong IV (bad padding)", strings.SplitN(good, "?iv=", 2)[0] + "?iv=AQEBAQEBAQEBAQEBAQEBAQ=="},
	}
	for _, c := range invalid {
		res := "accepted"
		if nip04Refuses(func() (string, error) { return nip04.Decrypt(c.payload, senderPub, nip04ReceiverSecret) }) {
			res = "refused"
		}
		f.Invalid = append(f.Invalid, nip04Invalid{c.name, c.payload, res})
	}
	return f, nil
}
