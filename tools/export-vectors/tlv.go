package main

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
)

// The four TLV string kinds cashkit decodes (design §2.1).
const (
	kindToken       = "token"
	kindCashHub     = "cashhub"
	kindCircleHub   = "circlehub"
	kindNConnection = "nconnection"
)

type tlvFile struct {
	header
	Decode []decodeCase `json:"decode"`
	Encode []encodeCase `json:"encode"`
}

// decodeCase: decoding Input as Kind either fails (Error set, Want absent)
// or yields Want.
type decodeCase struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Input string `json:"input"`
	Error string `json:"error,omitempty"`
	Want  any    `json:"want,omitempty"`
}

// encodeCase: encoding Fields as Kind either fails (Error set) or yields
// Output exactly.
type encodeCase struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Fields any    `json:"fields"`
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
}

// tokenJSON is a nipcash.Token in vector form. Byte fields are hex, the
// amount is a decimal string (it is a bigint in TypeScript), and every
// optional field is present with null meaning absent.
type tokenJSON struct {
	HRP                  string   `json:"hrp"`
	WalletPubkey         string   `json:"walletPubkey"`
	Secret               string   `json:"secret"`
	Relays               []string `json:"relays"`
	IdentityRequired     *bool    `json:"identityRequired"`
	MintSignature        *string  `json:"mintSignature"`
	AttestedAmountMillis *string  `json:"attestedAmountMillis"`
	HubGroup             *string  `json:"hubGroup"`
}

func tokenToJSON(t nipcash.Token) tokenJSON {
	out := tokenJSON{
		HRP:              t.HRP,
		WalletPubkey:     t.WalletPubkey,
		Secret:           t.Secret,
		Relays:           nonNil(t.RelayURLs),
		IdentityRequired: t.IdentityRequired,
	}
	if t.MintSignature != nil {
		out.MintSignature = strPtr(hex.EncodeToString(t.MintSignature))
	}
	if t.AttestedAmountMillis != nil {
		out.AttestedAmountMillis = strPtr(strconv.FormatUint(*t.AttestedAmountMillis, 10))
	}
	if t.HubGroup != nil {
		out.HubGroup = strPtr(hex.EncodeToString(t.HubGroup))
	}
	return out
}

func tokenFromJSON(j tokenJSON) nipcash.Token {
	t := nipcash.Token{
		HRP:              j.HRP,
		WalletPubkey:     j.WalletPubkey,
		Secret:           j.Secret,
		RelayURLs:        j.Relays,
		IdentityRequired: j.IdentityRequired,
	}
	if j.MintSignature != nil {
		t.MintSignature, _ = hex.DecodeString(*j.MintSignature)
	}
	if j.AttestedAmountMillis != nil {
		amt, _ := strconv.ParseUint(*j.AttestedAmountMillis, 10, 64)
		t.AttestedAmountMillis = &amt
	}
	if j.HubGroup != nil {
		t.HubGroup, _ = hex.DecodeString(*j.HubGroup)
	}
	return t
}

// hubJSON is a cashhub1 or circlehub1 connection; the two share a layout.
type hubJSON struct {
	WalletPubkey string   `json:"walletPubkey"`
	Secret       string   `json:"secret"`
	Relays       []string `json:"relays"`
	Label        string   `json:"label"`
}

type nconnectionJSON struct {
	ConnectionKey string   `json:"connectionKey"`
	Relays        []string `json:"relays"`
	Platform      string   `json:"platform"`
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type tlv struct {
	typ   byte
	value []byte
}

func tlvBytes(entries []tlv, raw []byte) []byte {
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteByte(e.typ)
		buf.WriteByte(byte(len(e.value)))
		buf.Write(e.value)
	}
	buf.Write(raw)
	return buf.Bytes()
}

func words(data []byte) []byte {
	w, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		panic(err)
	}
	return w
}

// bech32String hand-builds a TLV string, bypassing nmilat's encoders so that
// malformed inputs can be produced.
func bech32String(hrp string, entries []tlv, raw ...byte) string {
	s, err := bech32.Encode(hrp, words(tlvBytes(entries, raw)))
	if err != nil {
		panic(err)
	}
	return s
}

func bech32mString(hrp string, entries []tlv) string {
	s, err := bech32.EncodeM(hrp, words(tlvBytes(entries, nil)))
	if err != nil {
		panic(err)
	}
	return s
}

func decodeAs(kind, input string) (any, error) {
	switch kind {
	case kindToken:
		t, err := nipcash.Decode(input)
		if err != nil {
			return nil, err
		}
		return tokenToJSON(t), nil
	case kindCashHub:
		c, err := nipcash.DecodeCashHubConnection(input)
		if err != nil {
			return nil, err
		}
		return hubJSON{c.WalletPubkey, c.Secret, nonNil(c.RelayURLs), c.Label}, nil
	case kindCircleHub:
		c, err := nipcw.DecodeCircleHubConnection(input)
		if err != nil {
			return nil, err
		}
		return hubJSON{c.WalletPubkey, c.Secret, nonNil(c.RelayURLs), c.Label}, nil
	case kindNConnection:
		key, relays, platform, err := nipIC.DecodeNConnection(input)
		if err != nil {
			return nil, err
		}
		return nconnectionJSON{string(key), nonNil(relays), string(platform)}, nil
	}
	panic("unknown kind " + kind)
}

func encodeAs(kind string, fields any) (string, error) {
	switch kind {
	case kindToken:
		return nipcash.Encode(tokenFromJSON(fields.(tokenJSON)))
	case kindCashHub:
		f := fields.(hubJSON)
		return nipcash.EncodeCashHubConnection(nipcash.CashHubConnection{
			WalletPubkey: f.WalletPubkey, Secret: f.Secret, RelayURLs: f.Relays, Label: f.Label,
		})
	case kindCircleHub:
		f := fields.(hubJSON)
		return nipcw.EncodeCircleHubConnection(nipcw.CircleHubConnection{
			WalletPubkey: f.WalletPubkey, Secret: f.Secret, RelayURLs: f.Relays, Label: f.Label,
		})
	case kindNConnection:
		f := fields.(nconnectionJSON)
		return nipIC.EncodeNConnection(nipIC.ConnectionKey(f.ConnectionKey), f.Relays, nipIC.WebIdentity(f.Platform))
	}
	panic("unknown kind " + kind)
}

func decodeVector(name, kind, input string) decodeCase {
	want, err := decodeAs(kind, input)
	return decodeCase{Name: name, Kind: kind, Input: input, Error: errString(err), Want: want}
}

func encodeVector(name, kind string, fields any) encodeCase {
	out, err := encodeAs(kind, fields)
	return encodeCase{Name: name, Kind: kind, Fields: fields, Error: errString(err), Output: out}
}

var (
	fixKey    = repeat(0x22, 32)
	fixSecret = repeat(0x33, 32)
	fixURL    = []byte("wss://r.example")
	fixSig    = repeat(0x01, 65)
	fixAmount = []byte{0, 0, 0, 0, 0, 0, 0x52, 0x08} // 21000
	fixGroup  = nipcash.HubGroupFor(strings.Repeat("cd", 32))
)

func hrpFor(kind string) string {
	switch kind {
	case kindCashHub:
		return nipcash.CashHubConnectionHRP
	case kindCircleHub:
		return nipcw.CircleHubConnectionHRP
	case kindNConnection:
		return nipIC.NConnectionPrefix
	}
	return "lokicash"
}

func buildTLV() (any, error) {
	f := tlvFile{header: newHeader(
		"Decode and encode of the TLV bech32 strings: cash tokens (any HRP), cashhub1, circlehub1 and nconnection1.",
		"nipcash/token.go, cashhub_connection.go, nipcw/circlehub_connection.go, nipIC/nconnection.go; cases from decode_tlv_rules_test.go, token_test.go, hub_group_test.go, encode_relay_test.go, kat_test.go, nipcw/circlehub_tlv_rules_test.go",
	)}
	add := func(name, kind, input string) { f.Decode = append(f.Decode, decodeVector(name, kind, input)) }

	base := []tlv{{0, fixKey}, {1, fixURL}, {2, fixSecret}}
	with := func(extra ...tlv) []tlv { return append(append([]tlv{}, base...), extra...) }

	// Rules shared by the token, cashhub1 and circlehub1 decoders.
	shared := []struct {
		name    string
		entries []tlv
		raw     []byte
	}{
		{"minimal", base, nil},
		{"fields in any order", []tlv{{2, fixSecret}, {1, fixURL}, {0, fixKey}}, nil},
		{"two relays", with(tlv{1, []byte("wss://r2.example")}), nil},
		{"blank relay beside a real one is kept", with(tlv{1, []byte(" ")}), nil},
		{"empty relay beside a real one is kept", with(tlv{1, []byte{}}), nil},
		{"unknown types are ignored", []tlv{{0, fixKey}, {4, []byte{1, 2, 3}}, {1, fixURL}, {200, []byte("future")}, {2, fixSecret}}, nil},
		{"missing pubkey", []tlv{{1, fixURL}, {2, fixSecret}}, nil},
		{"missing secret", []tlv{{0, fixKey}, {1, fixURL}}, nil},
		{"duplicate pubkey", []tlv{{0, fixKey}, {0, fixKey}, {1, fixURL}, {2, fixSecret}}, nil},
		{"duplicate secret", with(tlv{2, fixSecret}), nil},
		{"short pubkey", []tlv{{0, fixKey[:31]}, {1, fixURL}, {2, fixSecret}}, nil},
		{"long secret", []tlv{{0, fixKey}, {1, fixURL}, {2, append(append([]byte{}, fixSecret...), 0)}}, nil},
		{"no relay", []tlv{{0, fixKey}, {2, fixSecret}}, nil},
		{"only blank relays", []tlv{{0, fixKey}, {1, []byte(" ")}, {1, []byte("\t")}, {2, fixSecret}}, nil},
		// Blank means Go's unicode.IsSpace, not JavaScript's trim().
		{"relay of U+0085 only is blank", []tlv{{0, fixKey}, {1, []byte("\u0085")}, {2, fixSecret}}, nil},
		{"relay of U+3000 only is blank", []tlv{{0, fixKey}, {1, []byte("\u3000")}, {2, fixSecret}}, nil},
		{"relay of U+FEFF only is not blank", []tlv{{0, fixKey}, {1, []byte("\ufeff")}, {2, fixSecret}}, nil},
		{"truncated entry", []tlv{{0, fixKey}, {1, fixURL}}, []byte{2, 32, 1, 2, 3}},
		{"lone type byte", base, []byte{9}},
		{"empty payload", nil, nil},
	}
	for _, kind := range []string{kindToken, kindCashHub, kindCircleHub} {
		for _, c := range shared {
			add(c.name, kind, bech32String(hrpFor(kind), c.entries, c.raw...))
		}
	}

	// Token only: any HRP, identity_required, provenance and hub group.
	for _, hrp := range []string{"satscash", "xyzcash", "a"} {
		add("hrp "+hrp, kindToken, bech32String(hrp, base))
	}
	add("identity_required 1", kindToken, bech32String("lokicash", with(tlv{3, []byte{1}})))
	add("identity_required 0", kindToken, bech32String("lokicash", with(tlv{3, []byte{0}})))
	add("identity_required two bytes", kindToken, bech32String("lokicash", with(tlv{3, []byte{0, 1}})))
	add("identity_required empty", kindToken, bech32String("lokicash", with(tlv{3, []byte{}})))
	add("identity_required value 2", kindToken, bech32String("lokicash", with(tlv{3, []byte{2}})))
	add("identity_required duplicate", kindToken, bech32String("lokicash", with(tlv{3, []byte{1}}, tlv{3, []byte{1}})))
	add("provenance pair", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount})))
	add("provenance amount before signature", kindToken, bech32String("lokicash", with(tlv{6, fixAmount}, tlv{5, fixSig})))
	add("provenance max amount", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, repeat(0xff, 8)})))
	add("provenance zero amount", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, make([]byte, 8)})))
	for _, c := range []struct {
		name  string
		extra []tlv
	}{
		{"signature alone", []tlv{{5, fixSig}}},
		{"amount alone", []tlv{{6, fixAmount}}},
		{"short signature", []tlv{{5, fixSig[:64]}, {6, fixAmount}}},
		{"long signature", []tlv{{5, append(append([]byte{}, fixSig...), 1)}, {6, fixAmount}}},
		{"short amount", []tlv{{5, fixSig}, {6, fixAmount[:7]}}},
		{"duplicate signature", []tlv{{5, fixSig}, {5, fixSig}, {6, fixAmount}}},
		{"duplicate amount", []tlv{{5, fixSig}, {6, fixAmount}, {6, fixAmount}}},
	} {
		add("anomalous provenance is dropped: "+c.name, kindToken, bech32String("lokicash", with(c.extra...)))
	}
	add("hub group", kindToken, bech32String("lokicash", with(tlv{7, fixGroup})))
	add("hub group with provenance", kindToken, bech32String("lokicash", with(tlv{5, fixSig}, tlv{6, fixAmount}, tlv{7, fixGroup})))
	for _, c := range []struct {
		name  string
		extra []tlv
	}{
		{"too short", []tlv{{7, []byte{1}}}},
		{"three bytes beside provenance", []tlv{{5, fixSig}, {6, fixAmount}, {7, []byte{1, 2, 3}}}},
		{"too long", []tlv{{7, repeat(1, 8)}}},
		{"empty", []tlv{{7, []byte{}}}},
		{"duplicated", []tlv{{7, fixGroup}, {7, fixGroup}}},
	} {
		add("anomalous hub group is dropped: "+c.name, kindToken, bech32String("lokicash", with(c.extra...)))
	}
	// A cashhub1 string read as a token: its label rides on type 3, which a
	// token reads as identity_required.
	add("cashhub label read as a token", kindToken, bech32String("cashhub", with(tlv{3, []byte("a")})))
	add("cashhub label byte 1 read as a token", kindToken, bech32String("cashhub", with(tlv{3, []byte{1}})))

	// Hub connections: label, and the HRP check.
	for _, kind := range []string{kindCashHub, kindCircleHub} {
		hrp := hrpFor(kind)
		add("label", kind, bech32String(hrp, with(tlv{3, []byte("Family hub")})))
		add("utf-8 label", kind, bech32String(hrp, with(tlv{3, []byte("Café ☕")})))
		add("empty label", kind, bech32String(hrp, with(tlv{3, []byte{}})))
		add("255-byte label", kind, bech32String(hrp, with(tlv{3, repeat('l', 255)})))
		add("duplicate label", kind, bech32String(hrp, with(tlv{3, []byte("a")}, tlv{3, []byte("b")})))
		add("duplicate empty label", kind, bech32String(hrp, with(tlv{3, []byte{}}, tlv{3, []byte{}})))
		add("wrong hrp", kind, bech32String("lokicash", base))
		add("other hub hrp", kind, bech32String(map[string]string{kindCashHub: "circlehub", kindCircleHub: "cashhub"}[kind], base))
		add("uppercase", kind, strings.ToUpper(bech32String(hrp, base)))
		add("bech32m checksum", kind, bech32mString(hrp, base))
	}

	// nconnection1 is looser: no duplicate checks, last value wins, and a
	// truncated tail is ignored rather than refused.
	ck := repeat(0x44, 32)
	nc := func(entries ...tlv) string { return bech32String("nconnection", entries) }
	add("key only", kindNConnection, nc(tlv{0, ck}))
	add("key, relays and platform", kindNConnection, nc(tlv{0, ck}, tlv{1, fixURL}, tlv{1, []byte("wss://r2.example")}, tlv{2, []byte("github")}))
	add("platform before key", kindNConnection, nc(tlv{2, []byte("x")}, tlv{0, ck}))
	add("unknown types are ignored", kindNConnection, nc(tlv{0, ck}, tlv{9, []byte("?")}))
	add("missing key", kindNConnection, nc(tlv{1, fixURL}))
	add("short key", kindNConnection, nc(tlv{0, ck[:31]}))
	add("duplicate key, last wins", kindNConnection, nc(tlv{0, ck}, tlv{0, repeat(0x55, 32)}))
	add("duplicate platform, last wins", kindNConnection, nc(tlv{0, ck}, tlv{2, []byte("github")}, tlv{2, []byte("x")}))
	add("blank relay is kept", kindNConnection, nc(tlv{0, ck}, tlv{1, []byte("")}))
	add("truncated tail is ignored", kindNConnection, bech32String("nconnection", []tlv{{0, ck}}, 1, 32, 'w', 's'))
	add("lone trailing byte is ignored", kindNConnection, bech32String("nconnection", []tlv{{0, ck}}, 1))
	add("truncated key", kindNConnection, bech32String("nconnection", nil, 0, 32, 1, 2))
	add("wrong prefix", kindNConnection, bech32String("lokicash", []tlv{{0, ck}}))
	add("uppercase", kindNConnection, strings.ToUpper(nc(tlv{0, ck})))
	add("bech32m checksum", kindNConnection, bech32mString("nconnection", []tlv{{0, ck}}))

	// bech32 framing, exercised through the token decoder.
	valid := bech32String("lokicash", base)
	add("framing: uppercase", kindToken, strings.ToUpper(valid))
	add("framing: bech32m checksum", kindToken, bech32mString("lokicash", base))
	add("framing: bad checksum", kindToken, flipLastChar(valid))
	add("framing: mixed case", kindToken, "L"+valid[1:])
	add("framing: character outside the charset", kindToken, replaceAt(valid, len("lokicash1")+3, 'b'))
	add("framing: character outside printable ASCII", kindToken, replaceAt(valid, 0, ' '))
	add("framing: no separator", kindToken, "lokicashqqqqqqqqqq")
	add("framing: empty hrp", kindToken, valid[len("lokicash"):])
	add("framing: shorter than 8", kindToken, "a1qqqqq")
	add("framing: data shorter than the checksum", kindToken, "lokicash1qqqqq")
	add("framing: hrp only, empty data", kindToken, mustEncodeWords("lokicash", nil))
	add("framing: hrp containing 1", kindToken, bech32String("loki1cash", base))
	add("framing: non-zero padding bits", kindToken, nonZeroPadding("lokicash", tlvBytes(with(tlv{1, []byte("x")}), nil)))
	add("framing: excess padding group", kindToken, excessPadding("lokicash", tlvBytes(with(tlv{1, []byte("x")}), nil)))
	add("framing: leading and trailing space", kindToken, " "+valid+" ")
	add("framing: empty string", kindToken, "")
	long := bech32String("lokicash", with(tlv{1, repeat('r', 255)}, tlv{1, repeat('s', 255)}, tlv{1, repeat('t', 255)}))
	add("framing: longer than bech32's 90-character limit", kindToken, long)

	f.Encode = buildTLVEncode()
	return f, nil
}

func flipLastChar(s string) string {
	last := s[len(s)-1]
	repl := byte('q')
	if last == 'q' {
		repl = 'p'
	}
	return s[:len(s)-1] + string(repl)
}

func replaceAt(s string, i int, c byte) string {
	b := []byte(s)
	b[i] = c
	return string(b)
}

func mustEncodeWords(hrp string, w []byte) string {
	s, err := bech32.Encode(hrp, w)
	if err != nil {
		panic(err)
	}
	return s
}

// nonZeroPadding sets a padding bit in the last 5-bit group, so the checksum
// is valid but the bit conversion is not.
func nonZeroPadding(hrp string, data []byte) string {
	if len(data)*8%5 == 0 {
		panic("data has no padding bits")
	}
	w := words(data)
	w[len(w)-1] |= 1
	return mustEncodeWords(hrp, w)
}

// excessPadding appends a whole extra zero group.
func excessPadding(hrp string, data []byte) string {
	return mustEncodeWords(hrp, append(words(data), 0))
}

func buildTLVEncode() []encodeCase {
	var out []encodeCase
	add := func(name, kind string, fields any) { out = append(out, encodeVector(name, kind, fields)) }

	key := hex.EncodeToString(fixKey)
	secret := hex.EncodeToString(fixSecret)
	relays := []string{string(fixURL)}
	amt := "21000"
	sig := hex.EncodeToString(fixSig)
	group := hex.EncodeToString(fixGroup)
	yes, no := true, false

	tok := func(mod func(*tokenJSON)) tokenJSON {
		t := tokenJSON{HRP: "lokicash", WalletPubkey: key, Secret: secret, Relays: relays}
		if mod != nil {
			mod(&t)
		}
		return t
	}
	add("token minimal", kindToken, tok(nil))
	add("token satscash", kindToken, tok(func(t *tokenJSON) { t.HRP = "satscash" }))
	add("token uppercase hrp is lowercased", kindToken, tok(func(t *tokenJSON) { t.HRP = "LOKICASH" }))
	add("token uppercase hex", kindToken, tok(func(t *tokenJSON) { t.WalletPubkey = strings.ToUpper(key) }))
	add("token identity_required true", kindToken, tok(func(t *tokenJSON) { t.IdentityRequired = &yes }))
	add("token identity_required false", kindToken, tok(func(t *tokenJSON) { t.IdentityRequired = &no }))
	add("token every field", kindToken, tok(func(t *tokenJSON) {
		t.Relays = []string{"wss://r1.example", "wss://r2.example"}
		t.IdentityRequired = &yes
		t.MintSignature, t.AttestedAmountMillis, t.HubGroup = &sig, &amt, &group
	}))
	add("token max amount", kindToken, tok(func(t *tokenJSON) {
		t.MintSignature, t.AttestedAmountMillis = &sig, strPtr("18446744073709551615")
	}))
	add("token blank relays are skipped", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{"", "wss://r.example", "  "} }))
	add("token 255-byte relay", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{strings.Repeat("r", 255)} }))
	add("token 256-byte relay", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{strings.Repeat("r", 256)} }))
	add("token no relays", kindToken, tok(func(t *tokenJSON) { t.Relays = nil }))
	add("token only blank relays", kindToken, tok(func(t *tokenJSON) { t.Relays = []string{" ", ""} }))
	add("token signature without amount", kindToken, tok(func(t *tokenJSON) { t.MintSignature = &sig }))
	add("token amount without signature", kindToken, tok(func(t *tokenJSON) { t.AttestedAmountMillis = &amt }))
	add("token 64-byte signature", kindToken, tok(func(t *tokenJSON) {
		t.MintSignature, t.AttestedAmountMillis = strPtr(sig[:128]), &amt
	}))
	add("token 2-byte hub group", kindToken, tok(func(t *tokenJSON) { t.HubGroup = strPtr("0102") }))
	add("token short pubkey", kindToken, tok(func(t *tokenJSON) { t.WalletPubkey = key[:62] }))
	add("token non-hex secret", kindToken, tok(func(t *tokenJSON) { t.Secret = "zz" + secret[2:] }))

	hub := func(mod func(*hubJSON)) hubJSON {
		h := hubJSON{WalletPubkey: key, Secret: secret, Relays: relays}
		if mod != nil {
			mod(&h)
		}
		return h
	}
	for _, kind := range []string{kindCashHub, kindCircleHub} {
		add(kind+" minimal", kind, hub(nil))
		add(kind+" label", kind, hub(func(h *hubJSON) { h.Label = "Family hub" }))
		add(kind+" 255-byte label", kind, hub(func(h *hubJSON) { h.Label = strings.Repeat("l", 255) }))
		add(kind+" 256-byte label", kind, hub(func(h *hubJSON) { h.Label = strings.Repeat("l", 256) }))
		add(kind+" blank relays are skipped", kind, hub(func(h *hubJSON) { h.Relays = []string{"", "wss://r.example", "  "} }))
		add(kind+" no relays", kind, hub(func(h *hubJSON) { h.Relays = nil }))
		add(kind+" 256-byte relay", kind, hub(func(h *hubJSON) { h.Relays = []string{strings.Repeat("r", 256)} }))
		add(kind+" short secret", kind, hub(func(h *hubJSON) { h.Secret = secret[:62] }))
	}

	ck := hex.EncodeToString(repeat(0x44, 32))
	add("nconnection key only", kindNConnection, nconnectionJSON{ConnectionKey: ck, Relays: []string{}})
	add("nconnection relays and platform", kindNConnection, nconnectionJSON{ck, []string{"wss://r1.example", "wss://r2.example"}, "github"})
	add("nconnection blank relay is written", kindNConnection, nconnectionJSON{ck, []string{""}, ""})
	add("nconnection short key", kindNConnection, nconnectionJSON{ck[:62], []string{}, ""})
	return out
}
