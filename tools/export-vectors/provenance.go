package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ohstr/nmilat/nipcash"
)

type provenanceFile struct {
	header
	MintPayload []mintPayloadCase `json:"mintPayload"`
	Prefix      []prefixCase      `json:"signedMessagePrefix"`
	Verify      []verifyCase      `json:"verify"`
}

type mintPayloadCase struct {
	HRP          string `json:"hrp"`
	WalletPubkey string `json:"walletPubkey"`
	AmountMillis string `json:"amountMillis"`
	Payload      string `json:"payload"`
}

// prefixCase: the signed-message prefix for HRP, null when the HRP has none
// (and so can carry no provenance).
type prefixCase struct {
	HRP    string  `json:"hrp"`
	Prefix *string `json:"prefix"`
}

// verifyCase: VerifyProvenance on the given token fields returns Minter (a
// compressed secp256k1 pubkey, hex) or null for no provenance. A tampered
// token usually still recovers SOME key, just not the true signer's; the
// vectors pin exactly which one.
type verifyCase struct {
	Name                 string  `json:"name"`
	HRP                  string  `json:"hrp"`
	WalletPubkey         string  `json:"walletPubkey"`
	MintSignature        *string `json:"mintSignature"`
	AttestedAmountMillis *string `json:"attestedAmountMillis"`
	Minter               *string `json:"minter"`
}

func privKey(b []byte) *secp256k1.PrivateKey { return secp256k1.PrivKeyFromBytes(b) }

func seq(from byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = from + byte(i)
	}
	return b
}

func doubleSHA256(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// signMint signs like a Lightning node's signmessage: a compact recoverable
// signature over sha256d(prefix || payload).
func signMint(priv *secp256k1.PrivateKey, prefix, hrp, wallet string, amount uint64, compressed bool) []byte {
	return ecdsa.SignCompact(priv, doubleSHA256([]byte(prefix+nipcash.MintPayload(hrp, wallet, amount))), compressed)
}

func buildProvenance() (any, error) {
	f := provenanceFile{header: newHeader(
		"Mint provenance: payload scheme, per-HRP signed-message prefix, and public-key recovery from the 65-byte compact signature over sha256d.",
		"nipcash/provenance.go; nipcash/kat_test.go, provenance_test.go; lokihub lokicash/lokicash_provenance_adversarial_test.go",
	)}

	walletA := hex.EncodeToString(repeat(0x22, 32))
	walletB := hex.EncodeToString(repeat(0x23, 32))

	for _, c := range []struct {
		hrp, wallet string
		amount      uint64
	}{
		{"lokicash", walletA, 21000},
		{"satscash", walletA, 0},
		{"xyzcash", walletB, 18446744073709551615},
	} {
		f.MintPayload = append(f.MintPayload, mintPayloadCase{c.hrp, c.wallet, strconv.FormatUint(c.amount, 10), nipcash.MintPayload(c.hrp, c.wallet, c.amount)})
	}
	for _, hrp := range []string{"lokicash", "satscash", "xyzcash", "LOKICASH", ""} {
		var p *string
		if s, ok := nipcash.SignedMessagePrefix(hrp); ok {
			p = &s
		}
		f.Prefix = append(f.Prefix, prefixCase{hrp, p})
	}

	add := func(name, hrp, wallet string, sig []byte, amount *uint64) {
		c := verifyCase{Name: name, HRP: hrp, WalletPubkey: wallet}
		tok := nipcash.Token{HRP: hrp, WalletPubkey: wallet, MintSignature: sig, AttestedAmountMillis: amount}
		if sig != nil {
			c.MintSignature = strPtr(hex.EncodeToString(sig))
		}
		if amount != nil {
			c.AttestedAmountMillis = strPtr(strconv.FormatUint(*amount, 10))
		}
		if m, ok := nipcash.VerifyProvenance(tok); ok {
			c.Minter = &m
		}
		f.Verify = append(f.Verify, c)
	}
	amt := func(v uint64) *uint64 { return &v }
	mustHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return b
	}

	// Frozen KATs from nipcash/kat_test.go: key 0x11..., wallet 0x22..., 21000.
	add("kat lokicash", "lokicash", walletA, mustHex("20c72cfbb8e8566000d6d90904c0c04fd047ce066dd599ede34c84dfb314f3126709ad9a50800f285c90a9683f8282b268a8bb85f8b7a9599f9b4482cbfd83b508"), amt(21000))
	add("kat satscash", "satscash", walletA, mustHex("1fcae9f6586ffbf8b1ee7e71eb3a531fc605573f2e04934899040d5237ef7280ad0a75647a2ebf91a982a93aaeaba324768e8b3a28e137bec9570d7f7e9d559b6c"), amt(21000))

	lokiPrefix := nipcash.LNSignedMessagePrefix
	lndPrefix := nipcash.LndSignedMessagePrefix
	signer := privKey(seq(33))
	other := privKey(seq(65))
	const a uint64 = 21000
	sigA := signMint(signer, lokiPrefix, "lokicash", walletA, a, true)
	sigB := signMint(signer, lokiPrefix, "lokicash", walletB, 40000, true)

	add("valid", "lokicash", walletA, sigA, amt(a))
	add("second token from the same signer", "lokicash", walletB, sigB, amt(40000))
	add("satscash under the lnd prefix", "satscash", walletA, signMint(signer, lndPrefix, "satscash", walletA, a, true), amt(a))
	add("satscash signed under the flnd prefix", "satscash", walletA, signMint(signer, lokiPrefix, "satscash", walletA, a, true), amt(a))
	add("lokicash signed under the lnd prefix", "lokicash", walletA, signMint(signer, lndPrefix, "lokicash", walletA, a, true), amt(a))
	add("zero amount", "lokicash", walletA, signMint(signer, lokiPrefix, "lokicash", walletA, 0, true), amt(0))
	add("max amount", "lokicash", walletA, signMint(signer, lokiPrefix, "lokicash", walletA, 18446744073709551615, true), amt(18446744073709551615))
	add("uncompressed recovery flag still yields the compressed key", "lokicash", walletA, signMint(signer, lokiPrefix, "lokicash", walletA, a, false), amt(a))

	// Tampering: recovery succeeds but yields a different key.
	add("tampered amount (inflate)", "lokicash", walletA, sigA, amt(a+1))
	add("tampered amount (deflate to zero)", "lokicash", walletA, sigA, amt(0))
	add("tampered wallet pubkey", "lokicash", walletB, sigA, amt(a))
	add("tampered hrp", "satscash", walletA, sigA, amt(a))
	add("swapped amount between two real tokens", "lokicash", walletA, sigA, amt(40000))
	add("signature from another node", "lokicash", walletA, signMint(other, lokiPrefix, "lokicash", walletA, a, true), amt(a))
	walletL := hex.EncodeToString(repeat(0xab, 32))
	sigL := signMint(signer, lokiPrefix, "lokicash", walletL, a, true)
	add("lowercase wallet pubkey with letters", "lokicash", walletL, sigL, amt(a))
	add("uppercase wallet pubkey is signed text, not bytes", "lokicash", strings.ToUpper(walletL), sigL, amt(a))

	// No provenance at all.
	add("unknown hrp", "xyzcash", walletA, signMint(signer, lokiPrefix, "xyzcash", walletA, a, true), amt(a))
	add("uppercase hrp", "LOKICASH", walletA, sigA, amt(a))
	add("signature without amount", "lokicash", walletA, sigA, nil)
	add("amount without signature", "lokicash", walletA, nil, amt(a))
	add("neither", "lokicash", walletA, nil, nil)
	add("short signature", "lokicash", walletA, sigA[:64], amt(a))
	add("all-zero signature", "lokicash", walletA, make([]byte, 65), amt(a))

	// Every recovery header byte around the valid range 27..34.
	for _, h := range []byte{0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 255} {
		sig := append([]byte{h}, sigA[1:]...)
		add(fmt.Sprintf("header byte %d", h), "lokicash", walletA, sig, amt(a))
	}
	// r or s out of range.
	zeroR := append(append([]byte{sigA[0]}, make([]byte, 32)...), sigA[33:]...)
	zeroS := append(append([]byte{}, sigA[:33]...), make([]byte, 32)...)
	maxR := append(append([]byte{sigA[0]}, repeat(0xff, 32)...), sigA[33:]...)
	add("r = 0", "lokicash", walletA, zeroR, amt(a))
	add("s = 0", "lokicash", walletA, zeroS, amt(a))
	add("r = 2^256-1", "lokicash", walletA, maxR, amt(a))
	add("high s with flipped recovery parity", "lokicash", walletA, highS(sigA), amt(a))
	return f, nil
}

// highS returns the malleated twin of a compact signature: s -> n - s, with
// the recovery parity flipped so the same key is recovered if high s is
// accepted.
func highS(sig []byte) []byte {
	var s secp256k1.ModNScalar
	s.SetByteSlice(sig[33:])
	s.Negate()
	out := append([]byte{}, sig[:33]...)
	sb := s.Bytes()
	out = append(out, sb[:]...)
	out[0] = 27 + (((sig[0] - 27) & 4) | (((sig[0] - 27) & 3) ^ 1))
	return out
}
