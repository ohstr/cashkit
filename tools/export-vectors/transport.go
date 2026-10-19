package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// ---- reply-key.json

type replyKeyFile struct {
	header
	Derive []replyKeyCase `json:"derive"`
}

type replyKeyCase struct {
	ConversationKey string `json:"conversationKey"`
	ReplyTo         string `json:"replyTo"`
	ReplyKey        string `json:"replyKey,omitempty"`
	Error           string `json:"error,omitempty"`
}

func buildReplyKey() (any, error) {
	f := replyKeyFile{header: newHeader(
		"The response key: HKDF-Expand(SHA-256, PRK = request conversation key, info = \"nipcash-reply-v1\" || reply_to hex, L = 32).",
		"nipcash/transport/response.go DeriveReplyKey; auditC_reply_key_kat_test.go",
	)}
	for _, c := range [][2]string{
		{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", strings.Repeat("00", 32)},
		{strings.Repeat("ff", 32), strings.Repeat("deadbeef", 8)},
		{"0e11ac12d17df2ba09c49b400df9aa1cba33288b42a099068bbcf05f6c910741", strings.Repeat("0123456789abcdef", 4)},
		{strings.Repeat("ab", 32), strings.Repeat("DEADBEEF", 8)},
		{strings.Repeat("ab", 32), strings.Repeat("00", 31)},
		{strings.Repeat("ab", 32), "zz" + strings.Repeat("00", 31)},
	} {
		var ck [32]byte
		copy(ck[:], mustHexBytes(c[0]))
		k, err := transport.DeriveReplyKey(ck, c[1])
		rc := replyKeyCase{ConversationKey: c[0], ReplyTo: c[1], Error: errString(err)}
		if err == nil {
			rc.ReplyKey = hex.EncodeToString(k[:])
		}
		f.Derive = append(f.Derive, rc)
	}
	return f, nil
}

// ---- canonical-params.json

type canonicalFile struct {
	header
	Hash []canonicalCase `json:"hash"`
}

// canonicalCase: CanonicalParamsHash(Params) is Hash, or fails. Canonical is
// the canonical text where the source test pins it.
type canonicalCase struct {
	Name      string `json:"name"`
	Params    string `json:"params"`
	Canonical string `json:"canonical,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Error     string `json:"error,omitempty"`
}

func buildCanonicalParams() (any, error) {
	f := canonicalFile{header: newHeader(
		"The params hash (ph) an item proof binds: sha256 of params with keys sorted by UTF-8 bytes, no whitespace, number literals verbatim and RFC 8785 string escaping. Not stock JCS.",
		"nipcash/transport/envelope.go CanonicalParamsHash; canonical_jcs_test.go",
	)}
	add := func(name, params, canonical string) {
		h, err := transport.CanonicalParamsHash(json.RawMessage(params))
		f.Hash = append(f.Hash, canonicalCase{Name: name, Params: params, Canonical: canonical, Hash: h, Error: errString(err)})
		if err != nil {
			f.Hash[len(f.Hash)-1].Hash = ""
		}
	}
	add("full form (TestCanonicalParams_RFC8785Strings)", "{\n\t\t\"z\": \"<>&\",\n\t\t\"q\": \"\\\"\\\\\\b\\t\\n\\f\\r\\u0001\\u001f\\u007f é\",\n\t\t\"n\": 12345678901234567890,\n\t\t\"arr\": [1.50, true, null],\n\t\t\"a\": \"x y z\"\n\t}",
		"{\"a\":\"x y z\",\"arr\":[1.50,true,null],\"n\":12345678901234567890,\"q\":\"\\\"\\\\\\b\\t\\n\\f\\r\\u0001\\u001f\x7f é\",\"z\":\"<>&\"}")
	for _, c := range [][3]string{
		{"less-than", `{"s":"<"}`, `{"s":"<"}`},
		{"greater-than", `{"s":">"}`, `{"s":">"}`},
		{"ampersand", `{"s":"&"}`, `{"s":"&"}`},
		{"U+2028", "{\"s\":\" \"}", "{\"s\":\" \"}"},
		{"U+2029 escaped in input", `{"s":" "}`, "{\"s\":\" \"}"},
		{"non-ASCII", `{"s":"é😀"}`, "{\"s\":\"é😀\"}"},
		{"escaped slash", `{"s":"\/"}`, `{"s":"/"}`},
		{"key with <", `{"<k":1}`, `{"<k":1}`},
		{"backspace", `{"s":"\u0008"}`, `{"s":"\b"}`},
		{"form feed", `{"s":"\u000c"}`, `{"s":"\f"}`},
		{"other control", `{"s":"\u000b"}`, `{"s":"\u000b"}`},
		{"escaped surrogate pair", `{"s":"😀"}`, "{\"s\":\"😀\"}"},
		{"lone surrogate becomes U+FFFD", `{"s":"\ud800"}`, "{\"s\":\"�\"}"},
		{"uppercase escape", `{"s":"é"}`, "{\"s\":\"é\"}"},
	} {
		add(c[0], c[1], c[2])
	}
	for _, c := range [][2]string{
		{"empty params hash as {}", ``},
		{"whitespace only", " \n\t"},
		{"empty object", `{}`},
		{"nested objects sort at every level", `{"b":{"z":1,"a":[{"y":2,"x":3}]},"a":0}`},
		{"keys sort by UTF-8 bytes", "{\"￿\":1,\"\U00010000\":2,\"é\":3,\"z\":4,\"Z\":5,\"\":6}"},
		{"duplicate keys: the last wins", `{"a":1,"a":2}`},
		{"number literals kept: 1.0", `{"n":1.0}`},
		{"number literals kept: 1e3", `{"n":1e3}`},
		{"number literals kept: 1E+03", `{"n":1E+03}`},
		{"number literals kept: -0", `{"n":-0}`},
		{"number literals kept: 0.1e-2", `{"n":0.1e-2}`},
		{"number beyond uint64", `{"n":123456789012345678901234567890}`},
		{"amount millis", `{"amount_millis":21000,"cash_secret":"ab"}`},
		{"top-level array", `[3,1,2]`},
		{"top-level string", `"x"`},
		{"top-level number", `42`},
		{"top-level null", `null`},
		{"trailing content", `{"a":1} {}`},
		{"trailing comma", `{"a":1,}`},
		{"not JSON", `{a:1}`},
		{"leading zero", `{"n":01}`},
		{"bare dot number", `{"n":.5}`},
		{"unescaped control in string", "{\"s\":\"a\x01b\"}"},
		{"real cash_transfer params", `{"identity_type":"pubkey","identity_value":"` + strings.Repeat("ab", 32) + `","identity_event":"{\"kind\":23198}","new_identity":{"identity_type":"cash","identity_value":"` + strings.Repeat("cd", 32) + `"},"amount_millis":5000}`},
	} {
		add(c[0], c[1], "")
	}
	return f, nil
}

// ---- padding.json

type paddingFile struct {
	header
	Defaults        limitsJSON      `json:"defaults"`
	PaddedSize      []paddedCase    `json:"paddedSize"`
	Validate        []validateCase  `json:"validate"`
	SourcesFor      [][2]int        `json:"maxSourcesForEnvelope"`
	ConsolidateSize [][2]int        `json:"estimatedConsolidateItemBytes"`
	WireBytes       []wireBytesCase `json:"estimatedWireBytes"`
	EnvelopeSizes   []envSizeCase   `json:"envelopeSizes"`
}

type limitsJSON struct {
	MaxEnvelopeBytes      int `json:"maxEnvelopeBytes"`
	MaxItems              int `json:"maxItems"`
	PadBucketBytes        int `json:"padBucketBytes"`
	MaxVerifyBudget       int `json:"maxVerifyBudget"`
	MaxConsolidateSources int `json:"maxConsolidateSources"`
}

func toLimitsJSON(l transport.Limits) limitsJSON {
	return limitsJSON{l.MaxEnvelopeBytes, l.MaxItems, l.PadBucketBytes, l.MaxVerifyBudget, l.MaxConsolidateSources}
}

func fromLimitsJSON(l limitsJSON) transport.Limits {
	return transport.Limits{MaxEnvelopeBytes: l.MaxEnvelopeBytes, MaxItems: l.MaxItems, PadBucketBytes: l.PadBucketBytes, MaxVerifyBudget: l.MaxVerifyBudget, MaxConsolidateSources: l.MaxConsolidateSources}
}

type paddedCase struct {
	Limits limitsJSON `json:"limits"`
	N      int        `json:"n"`
	Padded int        `json:"padded,omitempty"`
	Error  string     `json:"error,omitempty"`
}

// validateCase: Limits.Validate and ValidateAnnounced on Limits.
type validateCase struct {
	Name           string     `json:"name"`
	Limits         limitsJSON `json:"limits"`
	ValidError     string     `json:"validateError,omitempty"`
	AnnouncedError string     `json:"validateAnnouncedError,omitempty"`
}

type wireBytesCase struct {
	Limits    limitsJSON `json:"limits"`
	WireBytes int        `json:"wireBytes"`
}

// envSizeCase: the padded plaintext length of an envelope of N identical
// cash_status items, the property padding exists to blur.
type envSizeCase struct {
	Items int `json:"items"`
	Bytes int `json:"bytes"`
}

func buildPadding() (any, error) {
	f := paddingFile{header: newHeader(
		"Envelope limits: defaults, padded sizes, policy validation (local and announced) and size estimates.",
		"nipcash/transport/limits.go; limits_test.go, auditB_priv_padding_test.go, auditD_privacy_padding_test.go",
	)}
	d := transport.DefaultLimits()
	f.Defaults = toLimitsJSON(d)
	small := transport.Limits{MaxEnvelopeBytes: 10000, MaxItems: 4, PadBucketBytes: 1000, MaxVerifyBudget: 8, MaxConsolidateSources: 2}
	for _, l := range []transport.Limits{d, small} {
		for _, n := range []int{-1, 0, 1, 999, 1000, 1001, 8191, 8192, 8193, 57343, 57344, 57345, 10000, 10001} {
			p, err := l.PaddedSize(n)
			f.PaddedSize = append(f.PaddedSize, paddedCase{toLimitsJSON(l), n, p, errString(err)})
		}
	}
	mod := func(f func(*transport.Limits)) transport.Limits { l := d; f(&l); return l }
	for _, c := range []struct {
		name string
		l    transport.Limits
	}{
		{"defaults", d},
		{"small but coherent", small},
		{"zero items", mod(func(l *transport.Limits) { l.MaxItems = 0 })},
		{"zero bucket", mod(func(l *transport.Limits) { l.PadBucketBytes = 0 })},
		{"negative budget", mod(func(l *transport.Limits) { l.MaxVerifyBudget = -1 })},
		{"one consolidate source", mod(func(l *transport.Limits) { l.MaxConsolidateSources = 1 })},
		{"100 consolidate sources", mod(func(l *transport.Limits) { l.MaxConsolidateSources = 100 })},
		{"58 consolidate sources fits", mod(func(l *transport.Limits) { l.MaxConsolidateSources = 58 })},
		{"59 consolidate sources does not", mod(func(l *transport.Limits) { l.MaxConsolidateSources = 59 })},
		{"envelope at the NIP-44 ceiling", mod(func(l *transport.Limits) { l.MaxEnvelopeBytes = 65535 })},
		{"envelope above the NIP-44 ceiling", mod(func(l *transport.Limits) { l.MaxEnvelopeBytes = 65536 })},
		{"bucket larger than the envelope", mod(func(l *transport.Limits) { l.PadBucketBytes = 60000 })},
		{"announced bucket at the floor", mod(func(l *transport.Limits) { l.PadBucketBytes = 2048 })},
		{"announced bucket below the floor", mod(func(l *transport.Limits) { l.PadBucketBytes = 2047 })},
		{"announced bucket of 1", mod(func(l *transport.Limits) { l.PadBucketBytes = 1 })},
	} {
		f.Validate = append(f.Validate, validateCase{c.name, toLimitsJSON(c.l), errString(c.l.Validate()), errString(c.l.ValidateAnnounced())})
	}
	for _, n := range []int{0, 1000, 2914, 5000, 57344, 65535} {
		f.SourcesFor = append(f.SourcesFor, [2]int{n, transport.MaxSourcesForEnvelope(n)})
	}
	for _, n := range []int{-3, 0, 2, 10, 48, 100} {
		f.ConsolidateSize = append(f.ConsolidateSize, [2]int{n, transport.EstimatedConsolidateItemBytes(n)})
	}
	for _, l := range []transport.Limits{d, small} {
		f.WireBytes = append(f.WireBytes, wireBytesCase{toLimitsJSON(l), l.EstimatedWireBytes()})
	}
	for _, n := range []int{1, 2, 4, 8, 16, 32} {
		e := envelopeWith(n)
		pt, err := e.Encode(d)
		if err != nil {
			return nil, err
		}
		f.EnvelopeSizes = append(f.EnvelopeSizes, envSizeCase{n, len(pt)})
	}
	return f, nil
}

// ---- envelope.json

const (
	envNonce   = "1111111111111111111111111111111111111111111111111111111111111111"
	envReplyTo = "2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeProof is a structurally plausible proof object. Encode and Decode check
// shape only, never signatures, so a fixed object keeps the output exact.
const fakeProof = `{"id":"` + "aa" + `","kind":23192,"tags":[]}`
const fakeBillProof = `{"id":"bb","kind":23193,"tags":[]}`

func statusItem(i int) transport.Item {
	return transport.Item{
		ID:        fmt.Sprintf("i%d", i),
		Target:    fmt.Sprintf("%064x", i+1),
		Method:    "cash_status",
		Params:    json.RawMessage(`{"scope":"mine"}`),
		Proof:     json.RawMessage(fakeProof),
		BillProof: json.RawMessage(fakeBillProof),
	}
}

func envelopeWith(n int) transport.Envelope {
	e := transport.Envelope{Version: 1, NotAfter: 1760000060, Nonce: envNonce, ReplyTo: envReplyTo}
	for i := 0; i < n; i++ {
		e.Items = append(e.Items, statusItem(i))
	}
	return e
}

type envelopeFile struct {
	header
	Encode       []envEncodeCase  `json:"encode"`
	Decode       []envDecodeCase  `json:"decode"`
	Items        []itemInfoCase   `json:"items"`
	Freshness    []freshnessCase  `json:"freshness"`
	EncodeResp   []respEncodeCase `json:"encodeResponse"`
	DecodeResp   []respDecodeCase `json:"decodeResponse"`
	Validate     []coherenceCase  `json:"validate"`
	Servable     map[string]bool  `json:"servable"`
	NormalizeHub []normalizeCase  `json:"normalizeNodeIdentity"`
}

// envEncodeCase: Envelope.Encode(Limits) yields Plaintext byte for byte, or fails.
type envEncodeCase struct {
	Name      string       `json:"name"`
	Envelope  envelopeJSON `json:"envelope"`
	Limits    limitsJSON   `json:"limits"`
	Plaintext string       `json:"plaintext,omitempty"`
	Error     string       `json:"error,omitempty"`
}

// envDecodeCase: Decode keeps the items with ids Kept, rejects the ones at
// Rejected (indices into the received items), or fails outright.
type envDecodeCase struct {
	Name      string     `json:"name"`
	Plaintext string     `json:"plaintext"`
	Limits    limitsJSON `json:"limits"`
	Kept      []string   `json:"kept,omitempty"`
	Rejected  []int      `json:"rejected,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type itemInfoCase struct {
	Name         string   `json:"name"`
	Item         itemJSON `json:"item"`
	HasProof     bool     `json:"hasProof"`
	HasBillProof bool     `json:"hasBillProof"`
	IsBearer     bool     `json:"isBearer"`
	SourceCount  int      `json:"sourceCount"`
	Cost         int      `json:"verificationCost"`
}

type freshnessCase struct {
	NotAfter int64  `json:"notAfter"`
	Now      int64  `json:"now"`
	Error    string `json:"error,omitempty"`
}

type respEncodeCase struct {
	Name      string                     `json:"name"`
	Response  transport.ResponseEnvelope `json:"response"`
	Limits    limitsJSON                 `json:"limits"`
	Plaintext string                     `json:"plaintext,omitempty"`
	Error     string                     `json:"error,omitempty"`
}

type respDecodeCase struct {
	Name         string   `json:"name"`
	Plaintext    string   `json:"plaintext"`
	ReqNonce     string   `json:"reqNonce"`
	RequestedIDs []string `json:"requestedIds"`
	Error        string   `json:"error,omitempty"`
	Seq          int      `json:"seq,omitempty"`
	Total        int      `json:"total,omitempty"`
	Omitted      []string `json:"omitted,omitempty"`
}

type coherenceCase struct {
	Name     string       `json:"name"`
	Hub      string       `json:"hub"`
	Now      int64        `json:"now"`
	Envelope envelopeJSON `json:"envelope"`
	Error    string       `json:"error,omitempty"`
}

type normalizeCase struct {
	Input string `json:"input"`
	Want  string `json:"want,omitempty"`
	Error string `json:"error,omitempty"`
}

func buildEnvelope() (any, error) {
	f := envelopeFile{header: newHeader(
		"The private-transport envelope: exact encoded bytes (Go json.Marshal escaping, padding), decode with per-item rejection, item cost, freshness, response encode/decode, coherence validation.",
		"nipcash/transport/{envelope,response,validate,identity}.go; envelope_test.go, response_test.go, auditB_duplicate_item_test.go",
	)}
	d := transport.DefaultLimits()
	small := transport.Limits{MaxEnvelopeBytes: 10000, MaxItems: 4, PadBucketBytes: 1000, MaxVerifyBudget: 8, MaxConsolidateSources: 2}

	enc := func(name string, e transport.Envelope, l transport.Limits) {
		pt, err := e.Encode(l)
		f.Encode = append(f.Encode, envEncodeCase{name, toEnvJSON(e), toLimitsJSON(l), string(pt), errString(err)})
	}
	modItem := func(n int, f func(items []transport.Item) []transport.Item) transport.Envelope {
		e := envelopeWith(n)
		e.Items = f(e.Items)
		return e
	}
	enc("one cash_status", envelopeWith(1), d)
	enc("three items", envelopeWith(3), d)
	enc("small limits", envelopeWith(2), small)
	enc("html characters and U+2028 are escaped as Go does", modItem(1, func(it []transport.Item) []transport.Item {
		it[0].ID = "a<b>&c d"
		it[0].Params = json.RawMessage("{\"memo\": \"<&> \", \"n\": 1.50}")
		return it
	}), d)
	enc("params are compacted", modItem(1, func(it []transport.Item) []transport.Item {
		it[0].Params = json.RawMessage("{ \"scope\" :\n \"all\" }")
		return it
	}), d)
	enc("a bearer item needs no slice proof", modItem(1, func(it []transport.Item) []transport.Item {
		it[0].Params = json.RawMessage(`{"cash_secret":"` + strings.Repeat("5e", 32) + `"}`)
		it[0].Proof = nil
		return it
	}), d)
	enc("an incoming pad is replaced", func() transport.Envelope { e := envelopeWith(1); e.Pad = "xyz"; return e }(), d)
	enc("wrong version", func() transport.Envelope { e := envelopeWith(1); e.Version = 2; return e }(), d)
	enc("uppercase nonce", func() transport.Envelope { e := envelopeWith(1); e.Nonce = strings.Repeat("AB", 32); return e }(), d)
	enc("short reply_to", func() transport.Envelope { e := envelopeWith(1); e.ReplyTo = e.ReplyTo[:62]; return e }(), d)
	enc("no items", envelopeWith(0), d)
	enc("too many items", envelopeWith(5), small)
	enc("duplicate id", modItem(2, func(it []transport.Item) []transport.Item { it[1].ID = it[0].ID; return it }), d)
	enc("duplicate item", modItem(2, func(it []transport.Item) []transport.Item { it[1].Target = it[0].Target; return it }), d)
	enc("same item, params re-serialized", modItem(2, func(it []transport.Item) []transport.Item {
		it[1].Target = it[0].Target
		it[1].Params = json.RawMessage(`{ "scope" : "mine" }`)
		return it
	}), d)
	enc("same bill, different params is fine", modItem(2, func(it []transport.Item) []transport.Item {
		it[1].Target = it[0].Target
		it[1].Params = json.RawMessage(`{"scope":"all"}`)
		return it
	}), d)
	enc("empty id", modItem(1, func(it []transport.Item) []transport.Item { it[0].ID = ""; return it }), d)
	enc("256-byte id", modItem(1, func(it []transport.Item) []transport.Item { it[0].ID = strings.Repeat("x", 256); return it }), d)
	enc("257-byte id", modItem(1, func(it []transport.Item) []transport.Item { it[0].ID = strings.Repeat("x", 257); return it }), d)
	enc("uppercase target", modItem(1, func(it []transport.Item) []transport.Item { it[0].Target = strings.Repeat("AB", 32); return it }), d)
	enc("no method", modItem(1, func(it []transport.Item) []transport.Item { it[0].Method = ""; return it }), d)
	enc("no proof and no cash secret", modItem(1, func(it []transport.Item) []transport.Item { it[0].Proof = nil; return it }), d)
	enc("a null proof is no proof", modItem(1, func(it []transport.Item) []transport.Item { it[0].Proof = json.RawMessage("null"); return it }), d)
	enc("no bill proof", modItem(1, func(it []transport.Item) []transport.Item { it[0].BillProof = nil; return it }), d)
	enc("params not JSON", modItem(1, func(it []transport.Item) []transport.Item { it[0].Params = json.RawMessage(`{`); return it }), d)
	enc("too many consolidate sources", modItem(1, func(it []transport.Item) []transport.Item {
		it[0].Method = "cash_consolidate"
		it[0].Params = json.RawMessage(`{"sources":[{},{},{}]}`)
		return it
	}), small)
	enc("verification budget exceeded", envelopeWith(5), transport.Limits{MaxEnvelopeBytes: 10000, MaxItems: 8, PadBucketBytes: 1000, MaxVerifyBudget: 9, MaxConsolidateSources: 2})
	enc("too large after padding", envelopeWith(20), transport.Limits{MaxEnvelopeBytes: 3000, MaxItems: 32, PadBucketBytes: 1000, MaxVerifyBudget: 100, MaxConsolidateSources: 2})
	enc("invalid limits", envelopeWith(1), transport.Limits{})

	dec := func(name, pt string, l transport.Limits) {
		c := envDecodeCase{Name: name, Plaintext: pt, Limits: toLimitsJSON(l)}
		e, err := transport.Decode([]byte(pt), l)
		if err != nil {
			c.Error = err.Error()
		} else {
			for _, it := range e.Items {
				c.Kept = append(c.Kept, it.ID)
			}
			for _, r := range e.Rejected {
				c.Rejected = append(c.Rejected, r.Index)
			}
		}
		f.Decode = append(f.Decode, c)
	}
	good, _ := envelopeWith(3).Encode(d)
	dec("round trip", string(good), d)
	raw := func(e transport.Envelope) string { b, _ := json.Marshal(e); return string(b) }
	dec("one bad item is dropped, its co-items kept", raw(modItem(3, func(it []transport.Item) []transport.Item { it[1].Target = "nope"; return it })), d)
	dec("every item sharing an id is dropped", raw(modItem(3, func(it []transport.Item) []transport.Item { it[2].ID = it[0].ID; return it })), d)
	dec("a duplicate item: the first is kept", raw(modItem(2, func(it []transport.Item) []transport.Item { it[1].Target = it[0].Target; return it })), d)
	dec("no item survives: the first rejection is the error", raw(modItem(1, func(it []transport.Item) []transport.Item { it[0].BillProof = nil; return it })), d)
	dec("not JSON", "{", d)
	dec("wrong version", strings.Replace(raw(envelopeWith(1)), `"v":1`, `"v":2`, 1), d)
	dec("over the size limit", string(good)+strings.Repeat(" ", 57344), d)
	dec("budget counts surviving items only", raw(modItem(5, func(it []transport.Item) []transport.Item { it[4].Target = "nope"; return it })),
		transport.Limits{MaxEnvelopeBytes: 10000, MaxItems: 8, PadBucketBytes: 1000, MaxVerifyBudget: 8, MaxConsolidateSources: 2})
	dec("budget exceeded", raw(envelopeWith(5)), transport.Limits{MaxEnvelopeBytes: 10000, MaxItems: 8, PadBucketBytes: 1000, MaxVerifyBudget: 9, MaxConsolidateSources: 2})
	dec("unknown fields are ignored", strings.Replace(raw(envelopeWith(1)), `"v":1`, `"v":1,"extra":{"a":[1]}`, 1), d)
	dec("explicit null proof on a bearer item", strings.Replace(raw(modItem(1, func(it []transport.Item) []transport.Item {
		it[0].Params = json.RawMessage(`{"cash_secret":"ab"}`)
		it[0].Proof = nil
		return it
	})), `"bill_proof"`, `"proof":null,"bill_proof"`, 1), d)

	info := func(name string, it transport.Item) {
		f.Items = append(f.Items, itemInfoCase{name, toItemJSON(it), it.HasProof(), it.HasBillProof(), it.IsBearer(), it.SourceCount(), it.VerificationCost()})
	}
	info("pubkey-mode status", statusItem(0))
	bearer := statusItem(0)
	bearer.Params = json.RawMessage(`{"cash_secret":"ab"}`)
	bearer.Proof = nil
	info("bearer", bearer)
	emptySecret := statusItem(0)
	emptySecret.Params = json.RawMessage(`{"cash_secret":""}`)
	info("empty cash secret is not bearer", emptySecret)
	numSecret := statusItem(0)
	numSecret.Params = json.RawMessage(`{"cash_secret":1}`)
	info("non-string cash secret is not bearer", numSecret)
	cons := statusItem(0)
	cons.Method = "cash_consolidate"
	cons.Params = json.RawMessage(`{"sources":[{"identity_event":"{}"},{"identity_event":"{}","attestation_event":"{}"},{}]}`)
	info("consolidate counts nested proofs", cons)
	badSources := statusItem(0)
	badSources.Params = json.RawMessage(`{"sources":"x"}`)
	info("sources not an array", badSources)
	nullProof := statusItem(0)
	nullProof.Proof = json.RawMessage(" null ")
	info("a null proof is no proof", nullProof)

	for _, c := range [][2]int64{{1000, 999}, {1000, 1000}, {1000, 1001}, {1120, 1000}, {1121, 1000}, {1000, 2000}} {
		e := transport.Envelope{NotAfter: c[0]}
		f.Freshness = append(f.Freshness, freshnessCase{c[0], c[1], errString(e.CheckFreshness(time.Unix(c[1], 0)))})
	}

	encR := func(name string, r transport.ResponseEnvelope, l transport.Limits) {
		pt, err := r.EncodeResponse(l)
		f.EncodeResp = append(f.EncodeResp, respEncodeCase{name, r, toLimitsJSON(l), string(pt), errString(err)})
	}
	res := []transport.Result{
		{ID: "i0", ResultType: "cash_status", Result: json.RawMessage(`{"recipients":[{"identity_type":"cash","amount_millis":21000,"claimed":false}]}`)},
		{ID: "i1", ResultType: "cash_redeem", Error: &transport.ResultError{Code: "RESTRICTED", Message: "no <>"}},
	}
	encR("results and an error", transport.ResponseEnvelope{Version: 1, ReqNonce: envNonce, Results: res}, d)
	encR("chunk 2 of 3", transport.ResponseEnvelope{Version: 1, ReqNonce: envNonce, Results: res[:1], Seq: 2, Total: 3}, d)
	encR("envelope-level error", transport.ResponseEnvelope{Version: 1, ReqNonce: envNonce, Error: &transport.ResultError{Code: "RATE_LIMITED"}}, d)
	encR("seq past total", transport.ResponseEnvelope{Version: 1, ReqNonce: envNonce, Seq: 3, Total: 2}, d)
	encR("bad req_nonce", transport.ResponseEnvelope{Version: 1, ReqNonce: "x"}, d)

	decR := func(name, pt string, ids []string) {
		c := respDecodeCase{Name: name, Plaintext: pt, ReqNonce: envNonce, RequestedIDs: ids}
		r, err := transport.DecodeResponse([]byte(pt), envNonce, ids, d)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Seq, c.Total, c.Omitted = r.Seq, r.Total, r.Omitted(ids)
		}
		f.DecodeResp = append(f.DecodeResp, c)
	}
	full, _ := transport.ResponseEnvelope{Version: 1, ReqNonce: envNonce, Results: res}.EncodeResponse(d)
	decR("round trip", string(full), []string{"i0", "i1"})
	decR("an omitted item", string(full), []string{"i0", "i1", "i2"})
	decR("no seq or total means 1 of 1", `{"v":1,"req_nonce":"`+envNonce+`","results":[]}`, []string{"i0"})
	decR("another request's nonce", `{"v":1,"req_nonce":"`+envReplyTo+`"}`, []string{"i0"})
	decR("an unknown id", string(full), []string{"i0"})
	decR("a duplicate result", `{"v":1,"req_nonce":"`+envNonce+`","results":[{"id":"i0"},{"id":"i0"}]}`, []string{"i0"})
	decR("result and error together", `{"v":1,"req_nonce":"`+envNonce+`","results":[{"id":"i0","result":{},"error":{"code":"X"}}]}`, []string{"i0"})
	decR("seq 0 of 2", `{"v":1,"req_nonce":"`+envNonce+`","seq":0,"total":2}`, []string{"i0"})
	decR("wrong version", `{"v":2,"req_nonce":"`+envNonce+`"}`, []string{"i0"})
	decR("not JSON", `[`, []string{"i0"})

	// Coherence: real signed proofs, checked at a fixed instant.
	hubSec := strings.Repeat("07", 32)
	hub, _ := utils.GetPublicKey(hubSec)
	other, _ := utils.GetPublicKey(strings.Repeat("08", 32))
	const now = 1760000000
	coh := func(name, hubX string, e transport.Envelope) {
		f.Validate = append(f.Validate, coherenceCase{name, hubX, now, toEnvJSON(e), errString(e.Validate(hubX, time.Unix(now, 0)))})
	}
	signed := func(target, method, params, hubX string) transport.Item {
		ph, _ := transport.CanonicalParamsHash(json.RawMessage(params))
		b := transport.ProofBinding{Target: target, HubXOnly: hubX, Method: method, ParamsHash: ph, Nonce: envNonce, NotAfter: now + 60}
		return transport.Item{ID: "x" + target[:4], Target: target, Method: method, Params: json.RawMessage(params),
			Proof: signProof(transport.KindItemProof, claimantSecret, b, now), BillProof: signProof(transport.KindBillProof, strings.Repeat("09", 32), b, now)}
	}
	env := func(items ...transport.Item) transport.Envelope {
		return transport.Envelope{Version: 1, NotAfter: now + 60, Nonce: envNonce, ReplyTo: envReplyTo, Items: items}
	}
	t1, t2 := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	coh("coherent", hub, env(signed(t1, "cash_status", `{"scope":"mine"}`, hub)))
	coh("bearer item", hub, env(transport.Item{ID: "b", Target: t1, Method: "cash_redeem", Params: json.RawMessage(`{"cash_secret":"ab"}`), BillProof: json.RawMessage(fakeBillProof)}))
	coh("bearer item with a proof", hub, env(transport.Item{ID: "b", Target: t1, Method: "cash_redeem", Params: json.RawMessage(`{"cash_secret":"ab"}`), Proof: json.RawMessage(fakeProof), BillProof: json.RawMessage(fakeBillProof)}))
	coh("mixed hubs", hub, env(signed(t1, "cash_status", `{}`, hub), signed(t2, "cash_status", `{}`, other)))
	coh("not servable", hub, env(func() transport.Item { it := signed(t1, "mint_cash", `{}`, hub); return it }()))
	coh("params changed after signing", hub, env(func() transport.Item {
		it := signed(t1, "cash_status", `{"scope":"mine"}`, hub)
		it.Params = json.RawMessage(`{"scope":"all"}`)
		return it
	}()))
	coh("re-serialized params still match", hub, env(func() transport.Item {
		it := signed(t1, "cash_status", `{"scope":"mine"}`, hub)
		it.Params = json.RawMessage(`{ "scope" : "mine" }`)
		return it
	}()))
	coh("stale nonce", hub, func() transport.Envelope {
		e := env(signed(t1, "cash_status", `{}`, hub))
		e.Nonce = envReplyTo
		return e
	}())
	coh("uppercase hub", strings.ToUpper(hub), env(signed(t1, "cash_status", `{}`, hub)))
	coh("no items", hub, env())

	f.Servable = map[string]bool{}
	for _, m := range []string{"cash_status", "cash_redeem", "cash_transfer", "cash_consolidate", "create_circle_wallet", "mint_cash", "get_info", ""} {
		f.Servable[m] = transport.IsServableMethod(m)
	}
	for _, s := range []string{hub, "02" + hub, "03" + strings.ToUpper(hub), "04" + hub, " " + hub + "\n", hub[:62], "zz" + hub[2:]} {
		got, err := transport.NormalizeNodeIdentity(s)
		f.NormalizeHub = append(f.NormalizeHub, normalizeCase{s, got, errString(err)})
	}
	return f, nil
}

// signProof signs a kind-23192/23193 proof with a fixed created_at, as
// transport.buildProof does with the current time.
func signProof(kind int, secret string, b transport.ProofBinding, createdAt int64) json.RawMessage {
	ev := nip01.Event{Kind: kind, CreatedAt: uint64(createdAt), Tags: [][]string{
		{"d", b.Target}, {"h", b.HubXOnly}, {"m", b.Method}, {"ph", b.ParamsHash}, {"en", b.Nonce}, {"expiration", fmt.Sprint(b.NotAfter)},
	}}
	if err := ev.Sign(secret); err != nil {
		panic(err)
	}
	raw, _ := json.Marshal(ev)
	return raw
}

// ---- proof.json

type proofFile struct {
	header
	Build  []proofBuildCase  `json:"build"`
	Verify []proofVerifyCase `json:"verify"`
}

type proofBindingJSON struct {
	Target     string `json:"target"`
	Hub        string `json:"hub"`
	Method     string `json:"method"`
	ParamsHash string `json:"paramsHash"`
	Nonce      string `json:"nonce"`
	NotAfter   int64  `json:"notAfter"`
}

// proofBuildCase: BuildItemProof / BuildBillProof yield an event with these
// kind and tags (created_at is the current time, so it is not recorded).
type proofBuildCase struct {
	Name    string           `json:"name"`
	Kind    string           `json:"kind"`
	Binding proofBindingJSON `json:"binding"`
	Error   string           `json:"error,omitempty"`
	Tags    [][]string       `json:"tags,omitempty"`
	EvKind  int              `json:"eventKind,omitempty"`
}

// proofVerifyCase: VerifyItemProof / VerifyBillProof at Now yield Signer, or fail.
type proofVerifyCase struct {
	Name    string           `json:"name"`
	Kind    string           `json:"kind"`
	Proof   string           `json:"proof"`
	Binding proofBindingJSON `json:"binding"`
	Now     int64            `json:"now"`
	Signer  string           `json:"signer,omitempty"`
	Error   string           `json:"error,omitempty"`
}

func buildProofVectors() (any, error) {
	f := proofFile{header: newHeader(
		"Item (kind 23192) and bill (kind 23193) proofs: the six bound tags, and verification order, freshness window and kind separation.",
		"nipcash/transport/proof.go; proof_test.go, proof_window_test.go, bill_proof_test.go, nipcash/proof_binding_test.go",
	)}
	hub, _ := utils.GetPublicKey(strings.Repeat("07", 32))
	signer, _ := utils.GetPublicKey(claimantSecret)
	const now = 1760000000
	b := transport.ProofBinding{Target: strings.Repeat("a1", 32), HubXOnly: hub, Method: "cash_redeem", ParamsHash: strings.Repeat("c3", 32), Nonce: envNonce, NotAfter: now + 60}
	bj := func(b transport.ProofBinding) proofBindingJSON {
		return proofBindingJSON{b.Target, b.HubXOnly, b.Method, b.ParamsHash, b.Nonce, b.NotAfter}
	}

	build := func(name, kind string, b transport.ProofBinding) {
		var raw json.RawMessage
		var err error
		if kind == "item" {
			raw, err = transport.BuildItemProof(claimantSecret, b)
		} else {
			raw, err = transport.BuildBillProof(claimantSecret, b)
		}
		c := proofBuildCase{Name: name, Kind: kind, Binding: bj(b), Error: errString(err)}
		if err == nil {
			var ev nip01.Event
			_ = json.Unmarshal(raw, &ev)
			c.Tags, c.EvKind = ev.Tags, ev.Kind
		}
		f.Build = append(f.Build, c)
	}
	build("item proof", "item", b)
	build("bill proof", "bill", b)
	for _, fld := range []string{"target", "hub", "method", "paramsHash", "nonce"} {
		bb := b
		switch fld {
		case "target":
			bb.Target = ""
		case "hub":
			bb.HubXOnly = ""
		case "method":
			bb.Method = ""
		case "paramsHash":
			bb.ParamsHash = ""
		case "nonce":
			bb.Nonce = ""
		}
		build("missing "+fld, "item", bb)
	}

	verify := func(name, kind string, proof json.RawMessage, want transport.ProofBinding, at int64) {
		var s string
		var err error
		if kind == "item" {
			s, err = transport.VerifyItemProof(proof, want, time.Unix(at, 0))
		} else {
			s, err = transport.VerifyBillProof(proof, want, time.Unix(at, 0))
		}
		f.Verify = append(f.Verify, proofVerifyCase{name, kind, string(proof), bj(want), at, s, errString(err)})
	}
	item := signProof(transport.KindItemProof, claimantSecret, b, now)
	bill := signProof(transport.KindBillProof, claimantSecret, b, now)
	verify("valid item proof", "item", item, b, now)
	verify("valid bill proof", "bill", bill, b, now)
	verify("an item proof is not a bill proof", "bill", item, b, now)
	verify("a bill proof is not an item proof", "item", bill, b, now)
	for _, c := range []struct {
		name string
		mod  func(*transport.ProofBinding)
	}{
		{"wrong target", func(x *transport.ProofBinding) { x.Target = strings.Repeat("b2", 32) }},
		{"wrong hub", func(x *transport.ProofBinding) { x.HubXOnly = signer }},
		{"wrong method", func(x *transport.ProofBinding) { x.Method = "cash_transfer" }},
		{"wrong params", func(x *transport.ProofBinding) { x.ParamsHash = strings.Repeat("c4", 32) }},
		{"wrong envelope", func(x *transport.ProofBinding) { x.Nonce = envReplyTo }},
		{"different not_after is not checked", func(x *transport.ProofBinding) { x.NotAfter = 1 }},
	} {
		w := b
		c.mod(&w)
		verify(c.name, "item", item, w, now)
	}
	for _, at := range []int64{now - 60, now + 300, now + 301, now - 61} {
		verify(fmt.Sprintf("freshness: created %+ds from now", now-at), "item", item, b, at)
	}
	tagged := func(tags [][]string) json.RawMessage {
		ev := nip01.Event{Kind: transport.KindItemProof, CreatedAt: now, Tags: tags}
		_ = ev.Sign(claimantSecret)
		raw, _ := json.Marshal(ev)
		return raw
	}
	base := [][]string{{"d", b.Target}, {"h", hub}, {"m", b.Method}, {"ph", b.ParamsHash}, {"en", b.Nonce}, {"expiration", fmt.Sprint(b.NotAfter)}}
	verify("duplicate m tag", "item", tagged(append(append([][]string{}, base...), []string{"m", "cash_status"})), b, now)
	verify("duplicate identical tag", "item", tagged(append(append([][]string{}, base...), []string{"d", b.Target})), b, now)
	verify("missing ph tag", "item", tagged(append(append([][]string{}, base[:3]...), base[4:]...)), b, now)
	verify("empty en tag", "item", tagged([][]string{base[0], base[1], base[2], base[3], {"en", ""}}), b, now)
	verify("no expiration tag is fine", "item", tagged(base[:5]), b, now)
	verify("extra tags are ignored", "item", tagged(append(append([][]string{}, base...), []string{"x", "y"}, []string{"d"})), b, now)
	badSig := strings.Replace(string(item), `"sig":"`, `"sig":"00`, 1)
	badSig = strings.Replace(badSig, badSig[strings.Index(badSig, `"sig":"`)+7:strings.Index(badSig, `"sig":"`)+9], "", 0)
	var ev nip01.Event
	_ = json.Unmarshal(item, &ev)
	ev.Sig = flipHex(ev.Sig)
	flipped, _ := json.Marshal(ev)
	verify("bad signature", "item", flipped, b, now)
	_ = json.Unmarshal(item, &ev)
	ev.PubKey = strings.ToUpper(ev.PubKey)
	upper, _ := json.Marshal(ev)
	verify("uppercase signer pubkey", "item", upper, b, now)
	verify("not JSON", "item", json.RawMessage(`{`), b, now)
	verify("a JSON string, not an object", "item", json.RawMessage(`"x"`), b, now)
	return f, nil
}

// ---- announcement.json

type announcementFile struct {
	header
	Parse []announcementCase `json:"parse"`
}

type announcementCase struct {
	Name     string            `json:"name"`
	Event    nip01.Event       `json:"event"`
	Expected string            `json:"expectedNode"`
	Error    string            `json:"error,omitempty"`
	Want     *announcementJSON `json:"want,omitempty"`
}

type announcementJSON struct {
	Inbox     string     `json:"inbox"`
	Limits    limitsJSON `json:"limits"`
	Relays    []string   `json:"relays"`
	CreatedAt int64      `json:"createdAt"`
}

func buildAnnouncement() (any, error) {
	f := announcementFile{header: newHeader(
		"Kind 11190 Hub announcements: author must be the node identity, signature valid, inbox a valid key other than the node's, announced limits safe to adopt.",
		"nipcash/transport/announcement.go; announcement_test.go, auditC_seca_policy_floor_test.go",
	)}
	nodeSec := strings.Repeat("0a", 32)
	node, _ := utils.GetPublicKey(nodeSec)
	inbox, _ := utils.GetPublicKey(strings.Repeat("0b", 32))
	stranger, _ := utils.GetPublicKey(strings.Repeat("0c", 32))
	d := transport.DefaultLimits()

	sign := func(content string, kind int, secret string, at uint64) nip01.Event {
		ev := nip01.Event{Kind: kind, CreatedAt: at, Content: content}
		if err := ev.Sign(secret); err != nil {
			panic(err)
		}
		return ev
	}
	contentFor := func(inbox string, l transport.Limits, relays []string) string {
		ev, err := transport.NewAnnouncement(node, inbox, d, relays)
		if err != nil {
			panic(err)
		}
		if l != d {
			var a map[string]any
			_ = json.Unmarshal([]byte(ev.Content), &a)
			a["limits"] = map[string]int{"max_bytes": l.MaxEnvelopeBytes, "max_items": l.MaxItems, "max_consolidate_sources": l.MaxConsolidateSources, "pad_bucket_bytes": l.PadBucketBytes, "max_verify_budget": l.MaxVerifyBudget}
			raw, _ := json.Marshal(a)
			return string(raw)
		}
		return ev.Content
	}
	add := func(name string, ev nip01.Event, expected string) {
		c := announcementCase{Name: name, Event: ev, Expected: expected}
		a, err := transport.ParseAnnouncement(&ev, expected)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Want = &announcementJSON{a.Inbox, toLimitsJSON(a.Limits.Limits()), nonNil(a.Relays), a.CreatedAt}
		}
		f.Parse = append(f.Parse, c)
	}
	good := contentFor(inbox, d, []string{"wss://r1.example", "wss://r2.example"})
	add("valid", sign(good, 11190, nodeSec, 1760000000), node)
	add("no relays", sign(contentFor(inbox, d, nil), 11190, nodeSec, 1760000000), node)
	add("signed by someone else", sign(good, 11190, strings.Repeat("0c", 32), 1760000000), node)
	add("expected node given compressed is malformed", sign(good, 11190, nodeSec, 1760000000), "02"+node)
	add("expected node uppercase", sign(good, 11190, nodeSec, 1760000000), strings.ToUpper(node))
	add("wrong kind", sign(good, 10002, nodeSec, 1760000000), node)
	bad := sign(good, 11190, nodeSec, 1760000000)
	bad.Sig = flipHex(bad.Sig)
	add("bad signature", bad, node)
	add("inbox is the node key", sign(strings.Replace(good, inbox, node, 1), 11190, nodeSec, 1), node)
	add("inbox not on the curve", sign(strings.Replace(good, inbox, strings.Repeat("ff", 32), 1), 11190, nodeSec, 1), node)
	add("inbox uppercase", sign(strings.Replace(good, inbox, strings.ToUpper(inbox), 1), 11190, nodeSec, 1), node)
	add("version 2", sign(strings.Replace(good, `"v":1`, `"v":2`, 1), 11190, nodeSec, 1), node)
	add("content not JSON", sign("{", 11190, nodeSec, 1), node)
	add("bucket below the announce floor", sign(contentFor(inbox, func() transport.Limits { l := d; l.PadBucketBytes = 1; return l }(), nil), 11190, nodeSec, 1), node)
	add("envelope above the NIP-44 ceiling", sign(contentFor(inbox, func() transport.Limits { l := d; l.MaxEnvelopeBytes = 70000; return l }(), nil), 11190, nodeSec, 1), node)
	add("limits missing", sign(`{"v":1,"inbox":"`+inbox+`"}`, 11190, nodeSec, 1), node)
	add("unknown fields ignored", sign(strings.Replace(good, `"v":1`, `"v":1,"extra":true`, 1), 11190, nodeSec, 1), node)
	_ = stranger
	return f, nil
}

// envelopeJSON and itemJSON carry an envelope in vector form: params and
// proofs as raw text (null = absent), so malformed values can be recorded.
type envelopeJSON struct {
	Version  int        `json:"v"`
	NotAfter int64      `json:"not_after"`
	Nonce    string     `json:"nonce"`
	ReplyTo  string     `json:"reply_to"`
	Items    []itemJSON `json:"items"`
	Pad      string     `json:"pad"`
}

type itemJSON struct {
	ID        string  `json:"id"`
	Target    string  `json:"target"`
	Method    string  `json:"method"`
	Params    *string `json:"params"`
	Proof     *string `json:"proof"`
	BillProof *string `json:"bill_proof"`
}

func rawPtr(r json.RawMessage) *string {
	if r == nil {
		return nil
	}
	s := string(r)
	return &s
}

func toItemJSON(i transport.Item) itemJSON {
	return itemJSON{i.ID, i.Target, i.Method, rawPtr(i.Params), rawPtr(i.Proof), rawPtr(i.BillProof)}
}

func toEnvJSON(e transport.Envelope) envelopeJSON {
	items := []itemJSON{}
	for _, i := range e.Items {
		items = append(items, toItemJSON(i))
	}
	return envelopeJSON{e.Version, e.NotAfter, e.Nonce, e.ReplyTo, items, e.Pad}
}
