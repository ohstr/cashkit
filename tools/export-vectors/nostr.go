package main

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcw"
	"github.com/ohstr/nmilat/utils"
)

// ---- nip19.json

type nip19File struct {
	header
	Decode []nip19Case `json:"decode"`
	Encode []nip19Case `json:"encode"`
}

// nip19Case: decoding Input as Kind (or encoding Fields) fails or yields Want.
type nip19Case struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Input  string `json:"input,omitempty"`
	Fields any    `json:"fields,omitempty"`
	Error  string `json:"error,omitempty"`
	Want   any    `json:"want,omitempty"`
}

type profileJSON struct {
	Pubkey string   `json:"pubkey"`
	Relays []string `json:"relays"`
}

type eventPointerJSON struct {
	ID     string   `json:"id"`
	Relays []string `json:"relays"`
	Author string   `json:"author"`
	Kind   int      `json:"kind"`
}

type addrJSON struct {
	Identifier string   `json:"identifier"`
	Pubkey     string   `json:"pubkey"`
	Kind       int      `json:"kind"`
	Relays     []string `json:"relays"`
}

func buildNIP19() (any, error) {
	f := nip19File{header: newHeader(
		"NIP-19 bech32 entities as nmilat encodes and decodes them: npub, nsec, note, nprofile, nevent, naddr.",
		"nip19/nip19.go; nip19/{nip19,nprofile,pointer,pubkey}_test.go",
	)}
	dec := func(name, kind, input string) {
		c := nip19Case{Name: name, Kind: kind, Input: input}
		var want any
		var err error
		switch kind {
		case "npub":
			want, err = nip19.DecodePublicKey(input)
		case "nsec":
			want, err = nip19.DecodePrivateKey(input)
		case "note":
			want, err = nip19.DecodeNote(input)
		case "nprofile":
			var p *nip19.ProfilePointer
			if p, err = nip19.DecodeProfile(input); err == nil {
				want = profileJSON{p.PublicKey, nonNil(p.Relays)}
			}
		case "nevent":
			var p *nip19.EventPointer
			if p, err = nip19.DecodeEvent(input); err == nil {
				want = eventPointerJSON{p.ID, nonNil(p.Relays), p.Author, p.Kind}
			}
		case "naddr":
			var p *nip19.EntityPointer
			if p, err = nip19.DecodeAddr(input); err == nil {
				want = addrJSON{p.Identifier, p.PublicKey, p.Kind, nonNil(p.Relays)}
			}
		}
		c.Error, c.Want = errString(err), want
		if err != nil {
			c.Want = nil
		}
		f.Decode = append(f.Decode, c)
	}
	enc := func(name, kind string, fields any) {
		c := nip19Case{Name: name, Kind: kind, Fields: fields}
		var out string
		var err error
		switch kind {
		case "npub":
			out, err = nip19.EncodePublicKey(fields.(string))
		case "nsec":
			out, err = nip19.EncodePrivateKey(fields.(string))
		case "note":
			out, err = nip19.EncodeNote(fields.(string))
		case "nprofile":
			p := fields.(profileJSON)
			out, err = nip19.EncodeProfile(p.Pubkey, p.Relays)
		case "nevent":
			p := fields.(eventPointerJSON)
			out, err = nip19.EncodeEvent(nip19.EventPointer{ID: p.ID, Relays: p.Relays, Author: p.Author, Kind: p.Kind})
		case "naddr":
			p := fields.(addrJSON)
			out, err = nip19.EncodeAddr(nip19.EntityPointer{Identifier: p.Identifier, PublicKey: p.Pubkey, Kind: p.Kind, Relays: p.Relays})
		}
		c.Error = errString(err)
		if err == nil {
			c.Want = out
		}
		f.Encode = append(f.Encode, c)
	}

	k := strings.Repeat("7e", 32)
	for _, kind := range []string{"npub", "nsec", "note"} {
		enc(kind, kind, k)
		enc(kind+" uppercase hex", kind, strings.ToUpper(k))
		enc(kind+" any length is encoded", kind, k[:20])
		enc(kind+" non-hex", kind, "zz")
		dec(kind, kind, mustEncodeWords(kind, words(repeat(0x7e, 32))))
		dec(kind+" with extra bytes keeps the first 32", kind, mustEncodeWords(kind, words(repeat(0x7e, 40))))
		dec(kind+" shorter than 32 bytes", kind, mustEncodeWords(kind, words(repeat(0x7e, 31))))
		dec(kind+" wrong prefix", kind, mustEncodeWords("nfoo", words(repeat(0x7e, 32))))
	}
	dec("npub uppercase", "npub", strings.ToUpper(mustEncodeWords("npub", words(repeat(0x7e, 32)))))
	dec("npub bad checksum", "npub", flipLastChar(mustEncodeWords("npub", words(repeat(0x7e, 32)))))
	m, _ := bech32.EncodeM("npub", words(repeat(0x7e, 32)))
	dec("npub bech32m", "npub", m)

	pk := repeat(0x7e, 32)
	id := repeat(0x1d, 32)
	kind4 := []byte{0, 0, 0x75, 0x30} // 30000
	enc("nprofile", "nprofile", profileJSON{k, []string{"wss://r1", "wss://r2"}})
	enc("nprofile no relays", "nprofile", profileJSON{k, nil})
	enc("nprofile short pubkey", "nprofile", profileJSON{k[:62], nil})
	enc("nprofile long relay", "nprofile", profileJSON{k, []string{strings.Repeat("r", 256)}})
	dec("nprofile", "nprofile", bech32String("nprofile", []tlv{{0, pk}, {1, []byte("wss://r1")}, {1, []byte("wss://r2")}}))
	dec("nprofile unknown types ignored", "nprofile", bech32String("nprofile", []tlv{{9, []byte("x")}, {0, pk}}))
	dec("nprofile two pubkeys", "nprofile", bech32String("nprofile", []tlv{{0, pk}, {0, pk}}))
	dec("nprofile short pubkey", "nprofile", bech32String("nprofile", []tlv{{0, pk[:31]}}))
	dec("nprofile truncated tail ignored", "nprofile", bech32String("nprofile", []tlv{{0, pk}}, 1, 9, 'w'))
	dec("nprofile wrong prefix", "nprofile", bech32String("nevent", []tlv{{0, pk}}))

	enc("nevent full", "nevent", eventPointerJSON{hexs(id), []string{"wss://r"}, k, 30000})
	enc("nevent id only", "nevent", eventPointerJSON{ID: hexs(id)})
	enc("nevent bad author", "nevent", eventPointerJSON{ID: hexs(id), Author: "ab"})
	dec("nevent full", "nevent", bech32String("nevent", []tlv{{0, id}, {1, []byte("wss://r")}, {2, pk}, {3, kind4}}))
	dec("nevent id only", "nevent", bech32String("nevent", []tlv{{0, id}}))
	dec("nevent bad author ignored", "nevent", bech32String("nevent", []tlv{{0, id}, {2, pk[:5]}, {3, []byte{1}}}))
	dec("nevent duplicate author ignored", "nevent", bech32String("nevent", []tlv{{0, id}, {2, pk}, {2, pk}}))
	dec("nevent missing id", "nevent", bech32String("nevent", []tlv{{1, []byte("wss://r")}}))

	enc("naddr", "naddr", addrJSON{"my-list", k, 30000, []string{"wss://r"}})
	enc("naddr empty identifier", "naddr", addrJSON{"", k, 30000, nil})
	dec("naddr", "naddr", bech32String("naddr", []tlv{{0, []byte("my-list")}, {1, []byte("wss://r")}, {2, pk}, {3, kind4}}))
	dec("naddr empty identifier", "naddr", bech32String("naddr", []tlv{{0, nil}, {2, pk}, {3, kind4}}))
	dec("naddr missing kind", "naddr", bech32String("naddr", []tlv{{0, []byte("x")}, {2, pk}}))
	dec("naddr missing identifier", "naddr", bech32String("naddr", []tlv{{2, pk}, {3, kind4}}))
	dec("naddr two identifiers", "naddr", bech32String("naddr", []tlv{{0, []byte("a")}, {0, []byte("b")}, {2, pk}, {3, kind4}}))
	return f, nil
}

func hexs(b []byte) string { return hex.EncodeToString(b) }

// ---- nip47.json

type nip47File struct {
	header
	PairingBuild []pairingBuildCase `json:"pairingBuild"`
	PairingParse []pairingParseCase `json:"pairingParse"`
	Info         []infoCase         `json:"info"`
	Requests     []nwcRequestCase   `json:"requests"`
	Responses    []nwcResponseCase  `json:"responses"`
}

type pairingBuildCase struct {
	WalletPubkey string              `json:"walletPubkey"`
	Relays       []string            `json:"relays"`
	Secret       string              `json:"secret"`
	Extra        map[string][]string `json:"extra"`
	URI          string              `json:"uri"`
}

type pairingParseCase struct {
	Name  string       `json:"name"`
	URI   string       `json:"uri"`
	Error string       `json:"error,omitempty"`
	Want  *pairingJSON `json:"want,omitempty"`
}

type pairingJSON struct {
	WalletPubkey string              `json:"walletPubkey"`
	Relays       []string            `json:"relays"`
	Secret       string              `json:"secret"`
	Extra        map[string][]string `json:"extra"`
}

type infoCase struct {
	Name  string      `json:"name"`
	Event nip01.Event `json:"event"`
	Error string      `json:"error,omitempty"`
	Want  *infoJSON   `json:"want,omitempty"`
}

type infoJSON struct {
	Methods              []string `json:"methods"`
	NotificationTypes    []string `json:"notificationTypes"`
	SupportedEncryptions []string `json:"supportedEncryptions"`
}

// nwcRequestCase: a request event nmilat builds (signed here, with a fixed
// created_at); Plaintext is its decrypted content.
type nwcRequestCase struct {
	Name      string      `json:"name"`
	Method    string      `json:"method"`
	Params    any         `json:"params"`
	Event     nip01.Event `json:"event"`
	Plaintext string      `json:"plaintext"`
}

// nwcResponseCase: a response event as a wallet sends it; parsing it with the
// app's key and Fallback encryption fails or yields Want.
type nwcResponseCase struct {
	Name     string         `json:"name"`
	Event    nip01.Event    `json:"event"`
	Fallback string         `json:"fallback"`
	Error    string         `json:"error,omitempty"`
	Want     map[string]any `json:"want,omitempty"`
}

const (
	appSecret    = "0404040404040404040404040404040404040404040404040404040404040404"
	walletSecret = "0505050505050505050505050505050505050505050505050505050505050505"
)

func buildNIP47() (any, error) {
	f := nip47File{header: newHeader(
		"NIP-47: pairing URIs, info events, and nip44_v2 request and response events as nmilat builds and parses them.",
		"nip47/{pairing,events,methods}.go; nip47/{pairing,events,events_response_fallback}_test.go",
	)}
	walletPub, _ := utils.GetPublicKey(walletSecret)
	appPub, _ := utils.GetPublicKey(appSecret)

	for _, c := range []pairingBuildCase{
		{WalletPubkey: walletPub, Relays: []string{"wss://r1.example", "wss://r2.example"}, Secret: appSecret},
		{WalletPubkey: walletPub, Relays: []string{"wss://r.example/path?x=1&y=2"}, Secret: appSecret, Extra: map[string][]string{"lud16": {"a@b.example"}, "budget": {"1 000"}}},
		{WalletPubkey: walletPub, Relays: nil, Secret: "s p+a/c~e"},
	} {
		var extra url.Values
		if c.Extra != nil {
			extra = url.Values(c.Extra)
		}
		c.URI = nip47.BuildPairingURI(c.WalletPubkey, c.Relays, c.Secret, extra)
		if c.Relays == nil {
			c.Relays = []string{}
		}
		if c.Extra == nil {
			c.Extra = map[string][]string{}
		}
		f.PairingBuild = append(f.PairingBuild, c)
	}
	parse := func(name, uri string) {
		c := pairingParseCase{Name: name, URI: uri}
		p, err := nip47.ParsePairingURI(uri)
		if err != nil {
			c.Error = err.Error()
		} else {
			extra := map[string][]string(p.Extra)
			if extra == nil {
				extra = map[string][]string{}
			}
			c.Want = &pairingJSON{p.WalletPubkey, p.RelayURLs, p.Secret, extra}
		}
		f.PairingParse = append(f.PairingParse, c)
	}
	base := "nostr+walletconnect://" + walletPub
	parse("built URI", f.PairingBuild[0].URI)
	parse("extra parameters kept", f.PairingBuild[1].URI)
	parse("unescaped relay", base+"?relay=wss://r.example&secret="+appSecret)
	parse("plus is a space", base+"?relay=wss://r&secret=a+b")
	parse("repeated secret: the first wins", base+"?relay=wss://r&secret=one&secret=two")
	parse("uppercase scheme", "NOSTR+WALLETCONNECT://"+walletPub+"?relay=wss://r&secret=s")
	parse("uppercase pubkey", "nostr+walletconnect://"+strings.ToUpper(walletPub)+"?relay=wss://r&secret=s")
	parse("no slashes (opaque)", "nostr+walletconnect:"+walletPub+"?relay=wss://r&secret=s")
	parse("a fragment is dropped", base+"?relay=wss://r&secret=s#frag")
	parse("a path is ignored", base+"/path?relay=wss://r&secret=s")
	parse("userinfo before the pubkey", "nostr+walletconnect://user@"+walletPub+"?relay=wss://r&secret=s")
	parse("a port", base+":443?relay=wss://r&secret=s")
	parse("semicolon separator", base+"?relay=wss://r;secret=s")
	parse("a bad escape drops that pair", base+"?relay=wss://r&secret=s&x=%zz")
	parse("a bad escape in the secret", base+"?relay=wss://r&secret=%zz")
	parse("empty relay value", base+"?relay=&secret=s")
	parse("missing relay", base+"?secret=s")
	parse("missing secret", base+"?relay=wss://r")
	parse("empty secret", base+"?relay=wss://r&secret=")
	parse("wrong scheme", "nostr+walletconnec://"+walletPub+"?relay=wss://r&secret=s")
	parse("short pubkey", "nostr+walletconnect://"+walletPub[:62]+"?relay=wss://r&secret=s")
	parse("space in the URI", base+"?relay=wss://r&secret=a b")
	parse("control character", base+"?relay=wss://r\x01&secret=s")
	parse("not a URI", "%")

	info := func(name string, tags [][]string, content string, kind int) {
		ev := signedEvent(walletSecret, kind, tags, content)
		c := infoCase{Name: name, Event: ev}
		i, err := nip47.ParseInfoEvent(&ev)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Want = &infoJSON{nonNil(i.Methods), nonNil(i.NotificationTypes), nonNil(i.SupportedEncryptions)}
		}
		f.Info = append(f.Info, c)
	}
	info("methods, encryption and notifications", [][]string{{"encryption", "nip44_v2 nip04"}, {"notifications", "payment_received  payment_sent"}}, "pay_invoice get_balance  get_info", 13194)
	info("no encryption tag means nip04 only", nil, "get_info", 13194)
	info("empty content", [][]string{{"encryption", "nip44_v2"}}, "", 13194)
	info("duplicate encryption tag is ignored", [][]string{{"encryption", "nip44_v2"}, {"encryption", "nip04"}}, "get_info", 13194)
	info("empty encryption value keeps the default", [][]string{{"encryption", ""}}, "get_info", 13194)
	info("wrong kind", nil, "get_info", 1)

	// Encryption below uses crypto/rand for its nonce; seed it so the
	// ciphertexts, and therefore these vectors, are reproducible.
	type req struct {
		name, method string
		params       any
	}
	reqs := []req{
		{"get_info, no params", "get_info", nil},
		{"get_balance", "get_balance", nil},
		{"pay_invoice", "pay_invoice", nip47.PayInvoiceParams{Invoice: "lnfc10u1x"}},
		{"make_invoice", "make_invoice", nip47.MakeInvoiceParams{Amount: 21000, Description: "coffee"}},
		{"list_transactions", "list_transactions", nip47.ListTransactionsParams{Limit: i64(10), Unpaid: true}},
	}
	withSeededRand("nip47-requests", func() int {
		for _, r := range reqs {
			ev, err := nip47.NewRequestEvent(appSecret, walletPub, r.method, r.params, nip47.EncryptionNIP44V2)
			if err != nil {
				panic(err)
			}
			ev.CreatedAt = attTime
			if err := ev.Sign(appSecret); err != nil {
				panic(err)
			}
			parsed, err := nip47.ParseRequestEvent(ev, walletSecret)
			if err != nil {
				panic(err)
			}
			plain, _ := json.Marshal(parsed)
			f.Requests = append(f.Requests, nwcRequestCase{r.name, r.method, r.params, *ev, string(plain)})
		}
		return 0
	})

	reqEvent := f.Requests[0].Event
	resp := func(name string, ev *nip01.Event, fallback string) {
		c := nwcResponseCase{Name: name, Event: *ev, Fallback: fallback}
		r, err := nip47.ParseResponseEventWithFallback(ev, appSecret, fallback)
		if err != nil {
			c.Error = err.Error()
		} else {
			raw, _ := json.Marshal(r.Response)
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			m["request_event_id"] = r.RequestEventID
			m["sub_payment_id"] = r.SubPaymentID
			c.Want = m
		}
		f.Responses = append(f.Responses, c)
	}
	signResp := func(ev *nip01.Event) *nip01.Event {
		ev.CreatedAt = attTime
		if err := ev.Sign(walletSecret); err != nil {
			panic(err)
		}
		return ev
	}
	withSeededRand("nip47-responses", func() int {
		ok, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_balance", nip47.GetBalanceResult{BalanceMloki: 21000}, &reqEvent, nip47.EncryptionNIP44V2)
		resp("result", signResp(ok), nip47.EncryptionNIP44V2)
		e, _ := nip47.NewErrorResponseEvent(walletSecret, appPub, "pay_invoice", nip47.Error{Code: nip47.ErrInsufficientBalance, Message: "not enough"}, &reqEvent, nip47.EncryptionNIP44V2)
		resp("error", signResp(e), nip47.EncryptionNIP44V2)
		d, _ := nip47.NewResponseEvent(walletSecret, appPub, "multi_pay_invoice", nip47.PayInvoiceResult{Preimage: "ff"}, &reqEvent, nip47.EncryptionNIP44V2, []string{"d", "sub-1"})
		resp("sub-payment d tag", signResp(d), nip47.EncryptionNIP44V2)

		untagged, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_info", nip47.GetInfoResult{Methods: []string{"get_info"}}, &reqEvent, nip47.EncryptionNIP44V2)
		var kept [][]string
		for _, t := range untagged.Tags {
			if t[0] != "encryption" {
				kept = append(kept, t)
			}
		}
		untagged.Tags = kept
		resp("untagged nip44 response with a nip44 fallback", signResp(untagged), nip47.EncryptionNIP44V2)

		noE, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_balance", nil, &reqEvent, nip47.EncryptionNIP44V2)
		noE.Tags = [][]string{{"p", appPub}, {"encryption", "nip44_v2"}}
		resp("no e tag", signResp(noE), nip47.EncryptionNIP44V2)
		twoE, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_balance", nil, &reqEvent, nip47.EncryptionNIP44V2)
		twoE.Tags = append(twoE.Tags, []string{"e", "other"})
		resp("two e tags", signResp(twoE), nip47.EncryptionNIP44V2)
		twoD, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_balance", nil, &reqEvent, nip47.EncryptionNIP44V2, []string{"d", "1"}, []string{"d", "2"})
		resp("two d tags", signResp(twoD), nip47.EncryptionNIP44V2)
		wrongKind, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_balance", nil, &reqEvent, nip47.EncryptionNIP44V2)
		wrongKind.Kind = 23194
		resp("wrong kind", signResp(wrongKind), nip47.EncryptionNIP44V2)
		garbled, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_balance", nil, &reqEvent, nip47.EncryptionNIP44V2)
		garbled.Content = garbled.Content[:len(garbled.Content)-8] + "AAAAAAA="
		resp("undecryptable content", signResp(garbled), nip47.EncryptionNIP44V2)
		notJSON, _ := nip44.EncryptHex("not json", walletSecret, appPub)
		nj, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_balance", nil, &reqEvent, nip47.EncryptionNIP44V2)
		nj.Content = notJSON
		resp("content is not JSON", signResp(nj), nip47.EncryptionNIP44V2)
		unknown, _ := nip47.NewResponseEvent(walletSecret, appPub, "get_balance", nil, &reqEvent, nip47.EncryptionNIP44V2)
		unknown.Tags = [][]string{{"p", appPub}, {"e", reqEvent.ID}, {"encryption", "rot13"}}
		resp("unknown encryption tag", signResp(unknown), nip47.EncryptionNIP44V2)
		return 0
	})
	return f, nil
}

func i64(v int64) *int64 { return &v }

// ---- nipcw.json

type nipcwFile struct {
	header
	Requests []circleRequestCase `json:"requests"`
	Results  []circleResultCase  `json:"results"`
}

type circleRequestCase struct {
	Name    string         `json:"name"`
	Inputs  map[string]any `json:"inputs"`
	Error   string         `json:"error,omitempty"`
	Request map[string]any `json:"request,omitempty"`
}

type circleResultCase struct {
	Name   string         `json:"name"`
	Result string         `json:"result"`
	Error  string         `json:"error,omitempty"`
	Want   map[string]any `json:"want,omitempty"`
}

const hubSecret = "0606060606060606060606060606060606060606060606060606060606060606"

func buildNIPCW() (any, error) {
	f := nipcwFile{header: newHeader(
		"NIP-CW create_circle_wallet: the request with its kind 23199 identity proof, and the result with its encrypted wallet details.",
		"nipcw/{create_circle_wallet,identity,connection_key}.go; nipcw/{create_circle_wallet,connection_key_kat}_test.go",
	)}
	hubPub, _ := utils.GetPublicKey(hubSecret)
	memberPub, _ := utils.GetPublicKey(claimantSecret)
	conn, _ := nipcw.ConnectionKeyFromSecret(strings.Repeat("11", 32))
	self, _ := nipcw.ConnectionKeyFromSecret(claimantSecret)

	req := func(name string, p nipcw.CreateCircleWalletParams, inputs map[string]any) {
		c := circleRequestCase{Name: name, Inputs: inputs}
		r, err := p.Request(hubPub)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Request = flattenRequest(r)
		}
		f.Requests = append(f.Requests, c)
	}
	in := func(conn string, max uint64, expiry int, renewal string) map[string]any {
		return map[string]any{"hub": hubPub, "connectionSecret": conn, "maxAmountMillis": max, "expirySeconds": expiry, "budgetRenewal": renewal}
	}
	req("full", nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(claimantSecret), Connection: conn, MaxAmountMillis: 100000, Expiry: 30 * 24 * time.Hour, BudgetRenewal: "monthly"}, in(conn.Secret(), 100000, 2592000, "monthly"))
	req("no budget renewal", nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(claimantSecret), Connection: conn, MaxAmountMillis: 1}, in(conn.Secret(), 1, 0, ""))
	req("sub-second expiry truncates", nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(claimantSecret), Connection: conn, Expiry: 1500 * time.Millisecond}, in(conn.Secret(), 0, 1, ""))
	req("no connection key", nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(claimantSecret)}, in("", 0, 0, ""))
	req("connection key equal to the member key", nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(claimantSecret), Connection: self}, in(claimantSecret, 0, 0, ""))

	p := nipcw.CreateCircleWalletParams{Credential: nipcw.BySigning(claimantSecret), Connection: conn}
	result := func(name string, data string) {
		c := circleResultCase{Name: name, Result: data}
		r, err := p.ParseResult(hubPub, []byte(data))
		if err != nil {
			c.Error = err.Error()
		} else {
			raw, _ := json.Marshal(r)
			_ = json.Unmarshal(raw, &c.Want)
		}
		f.Results = append(f.Results, c)
	}
	seal := func(details string) string {
		ct, err := nip44.EncryptHex(details, hubSecret, memberPub)
		if err != nil {
			panic(err)
		}
		raw, _ := json.Marshal(map[string]string{"encrypted_details": ct})
		return string(raw)
	}
	w := strings.Repeat("9a", 32)
	withSeededRand("nipcw-results", func() int {
		result("full details", seal(`{"wallet_pubkey":"`+w+`","relays":["wss://r1.example","wss://r2.example"],"max_amount":100000,"expires_at":1800000000,"fees_ppm":2500,"budget_renewal":"monthly"}`))
		result("minimal details", seal(`{"wallet_pubkey":"`+w+`","relays":["wss://r1.example"]}`))
		result("blank relays are dropped", seal(`{"wallet_pubkey":"`+w+`","relays":[" ","wss://r1.example",""]}`))
		result("only blank relays", seal(`{"wallet_pubkey":"`+w+`","relays":[" "]}`))
		result("no relays", seal(`{"wallet_pubkey":"`+w+`"}`))
		result("bad wallet pubkey", seal(`{"wallet_pubkey":"abc","relays":["wss://r"]}`))
		result("uppercase wallet pubkey", seal(`{"wallet_pubkey":"`+strings.ToUpper(w)+`","relays":["wss://r"]}`))
		result("details not JSON", seal(`nope`))
		result("max_amount as a string", seal(`{"wallet_pubkey":"`+w+`","relays":["wss://r"],"max_amount":"1"}`))
		result("no encrypted_details", `{}`)
		result("result not JSON", `[`)
		result("details sealed to someone else", func() string {
			ct, _ := nip44.EncryptHex(`{"wallet_pubkey":"`+w+`","relays":["wss://r"]}`, hubSecret, hubPub)
			raw, _ := json.Marshal(map[string]string{"encrypted_details": ct})
			return string(raw)
		}())
		return 0
	})
	return f, nil
}
