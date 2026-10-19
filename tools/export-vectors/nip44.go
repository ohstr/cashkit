package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ohstr/nmilat/nip44"
)

// The upstream NIP-44 vectors (github.com/paulmillr/nip44), vendored. The
// NIP publishes this file's sha256; a different file is refused.
//
//go:embed testdata/nip44.vectors.json
var upstreamNIP44 []byte

const upstreamNIP44SHA256 = "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040"

type nip44File struct {
	header
	// Checked lists the upstream groups nmilat was run against and agreed
	// with. The other groups need a caller-chosen nonce, which nmilat's
	// Encrypt does not take, so only cashkit checks them.
	Checked []string `json:"checkedAgainstNmilat"`
	// Divergences lists upstream cases where nmilat does not do what the NIP
	// says. cashkit follows the NIP there.
	Divergences []string        `json:"nmilatDivergences"`
	V2          json.RawMessage `json:"v2"`
}

type upstreamV2 struct {
	Valid struct {
		GetConversationKey []struct {
			Sec1            string `json:"sec1"`
			Pub2            string `json:"pub2"`
			ConversationKey string `json:"conversation_key"`
		} `json:"get_conversation_key"`
		CalcPaddedLen  [][2]int `json:"calc_padded_len"`
		EncryptDecrypt []struct {
			Sec1            string `json:"sec1"`
			Sec2            string `json:"sec2"`
			ConversationKey string `json:"conversation_key"`
			Plaintext       string `json:"plaintext"`
			Payload         string `json:"payload"`
		} `json:"encrypt_decrypt"`
	} `json:"valid"`
	Invalid struct {
		EncryptMsgLengths []int `json:"encrypt_msg_lengths"`
		Decrypt           []struct {
			ConversationKey string `json:"conversation_key"`
			Payload         string `json:"payload"`
			Note            string `json:"note"`
		} `json:"decrypt"`
	} `json:"invalid"`
}

func buildNIP44() (any, error) {
	if sum := sha256.Sum256(upstreamNIP44); hex.EncodeToString(sum[:]) != upstreamNIP44SHA256 {
		return nil, fmt.Errorf("vendored nip44.vectors.json has sha256 %x, want %s", sum, upstreamNIP44SHA256)
	}
	var doc struct {
		V2 json.RawMessage `json:"v2"`
	}
	if err := json.Unmarshal(upstreamNIP44, &doc); err != nil {
		return nil, err
	}
	var v upstreamV2
	if err := json.Unmarshal(doc.V2, &v); err != nil {
		return nil, err
	}

	for i, c := range v.Valid.GetConversationKey {
		pub, err := liftX(c.Pub2)
		if err != nil {
			return nil, fmt.Errorf("get_conversation_key[%d]: %w", i, err)
		}
		if err := checkConversationKey(c.Sec1, pub, c.ConversationKey); err != nil {
			return nil, fmt.Errorf("get_conversation_key[%d]: %w", i, err)
		}
	}
	for i, c := range v.Valid.EncryptDecrypt {
		pub2 := secp256k1.PrivKeyFromBytes(mustHexBytes(c.Sec2)).PubKey()
		if err := checkConversationKey(c.Sec1, pub2, c.ConversationKey); err != nil {
			return nil, fmt.Errorf("encrypt_decrypt[%d]: %w", i, err)
		}
		got, err := nip44.Decrypt(c.Payload, mustHexBytes(c.ConversationKey))
		if err != nil || got != c.Plaintext {
			return nil, fmt.Errorf("encrypt_decrypt[%d]: nmilat decrypts to (%q, %v), want %q", i, got, err, c.Plaintext)
		}
	}
	ck := mustHexBytes(strings.Repeat("ab", 32))
	for _, c := range v.Valid.CalcPaddedLen {
		payload, err := nip44.Encrypt(strings.Repeat("a", c[0]), ck)
		if err != nil {
			return nil, fmt.Errorf("calc_padded_len %d: %w", c[0], err)
		}
		raw, _ := base64.StdEncoding.DecodeString(payload)
		// version(1) || nonce(32) || u16 length(2) || padded || mac(32)
		if got := len(raw) - 1 - 32 - 2 - 32; got != c[1] {
			return nil, fmt.Errorf("calc_padded_len %d: nmilat pads to %d, want %d", c[0], got, c[1])
		}
	}
	// nmilat's Encrypt has no length check, so it seals out-of-range
	// plaintexts that no conforming peer can open. cashkit follows the NIP
	// and refuses them; the divergence is recorded rather than hidden.
	var divergences []string
	for _, n := range v.Invalid.EncryptMsgLengths {
		if _, err := nip44.Encrypt(strings.Repeat("a", n), ck); err == nil {
			divergences = append(divergences, fmt.Sprintf("invalid.encrypt_msg_lengths: nmilat encrypts a %d-byte plaintext; cashkit refuses it as the NIP requires", n))
		}
	}
	for i, c := range v.Invalid.Decrypt {
		if got, err := nip44.Decrypt(c.Payload, mustHexBytes(c.ConversationKey)); err == nil {
			return nil, fmt.Errorf("invalid.decrypt[%d] (%s): nmilat decrypted it to %q", i, c.Note, got)
		}
	}

	return nip44File{
		header: newHeader(
			"NIP-44 v2: the upstream vectors, verbatim, after checking that nmilat agrees with them.",
			"nip44/encryption.go; nip44/auditC_qa_kat_test.go; upstream github.com/paulmillr/nip44 nip44.vectors.json (sha256 "+upstreamNIP44SHA256+")",
		),
		Checked: []string{
			"valid.get_conversation_key",
			"valid.calc_padded_len",
			"valid.encrypt_decrypt (conversation key and decrypt)",
			"invalid.decrypt",
		},
		Divergences: divergences,
		V2:          doc.V2,
	}, nil
}

func checkConversationKey(sec1Hex string, pub *secp256k1.PublicKey, want string) error {
	got, err := nip44.GenerateConversationKey(secp256k1.PrivKeyFromBytes(mustHexBytes(sec1Hex)), pub)
	if err != nil {
		return err
	}
	if hex.EncodeToString(got) != want {
		return fmt.Errorf("nmilat conversation key %x, want %s", got, want)
	}
	return nil
}

// liftX parses a BIP-340 x-only pubkey (even y).
func liftX(xHex string) (*secp256k1.PublicKey, error) {
	return secp256k1.ParsePubKey(append([]byte{2}, mustHexBytes(xHex)...))
}

func mustHexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
