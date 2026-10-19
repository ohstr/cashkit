package main

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

type nip01File struct {
	header
	Serialize []serializeCase   `json:"serialize"`
	Verify    []verifyEventCase `json:"verify"`
}

// serializeCase: nmilat's event serialization and id for an unsigned event.
// nmilat escapes tags with Go's encoding/json and content with its own
// escaper; both differ from NIP-01 for some characters, and the Hub hashes
// what nmilat hashes, so cashkit must produce exactly these bytes.
type serializeCase struct {
	Name       string     `json:"name"`
	Pubkey     string     `json:"pubkey"`
	CreatedAt  uint64     `json:"created_at"`
	Kind       int        `json:"kind"`
	Tags       [][]string `json:"tags"`
	Content    string     `json:"content"`
	Serialized string     `json:"serialized"`
	ID         string     `json:"id"`
}

// verifyEventCase: nmilat's Event.Verify on Event either passes (Valid) or not.
type verifyEventCase struct {
	Name  string      `json:"name"`
	Event nip01.Event `json:"event"`
	Valid bool        `json:"valid"`
	Error string      `json:"error,omitempty"`
}

const (
	evSecret = "0101010101010101010101010101010101010101010101010101010101010101"
	evTime   = 1760000000
)

func buildNIP01() (any, error) {
	f := nip01File{header: newHeader(
		"NIP-01 events as nmilat serializes, hashes, signs and verifies them, including its JSON escaping and NIP-13 nonce check.",
		"nip01/event.go, utils/event.go MarshalTags/EscapeJSONString, nip13/nip13.go ValidatePow; nip01/event_test.go",
	)}
	pub := strings.Repeat("ab", 32)

	ser := func(name, pubkey string, kind int, tags [][]string, content string) {
		ev := nip01.Event{PubKey: pubkey, CreatedAt: evTime, Kind: kind, Tags: tags, Content: content}
		s, err := ev.Serialize()
		if err != nil {
			panic(err)
		}
		id, _ := ev.HashID()
		f.Serialize = append(f.Serialize, serializeCase{name, pubkey, evTime, kind, tags, content, string(s), hex.EncodeToString(id)})
	}
	ser("empty", pub, 1, [][]string{}, "")
	ser("nil tags serialize as []", pub, 1, nil, "")
	ser("claim proof shape", pub, 23198, [][]string{{"d", pub}, {"bolt11_hash", strings.Repeat("cd", 32)}, {"amount_millis", "21000"}}, "")
	ser("uppercase pubkey is lowercased", strings.ToUpper(pub), 1, nil, "hi")
	ser("empty tag and empty tag value", pub, 1, [][]string{{}, {""}, {"e", ""}}, "")
	for _, c := range []struct{ name, s string }{
		{"quote and backslash", `say "hi" \ bye`},
		{"newline, return, tab", "a\nb\rc\td"},
		{"backspace and form feed", "a\bb\fc"},
		{"other C0 controls", "\x00\x01\x1b\x1f"},
		{"DEL", "a\x7fb"},
		{"html characters", "<a href=\"x\">&amp;</a>"},
		{"line and paragraph separators", "a b c"},
		{"non-ASCII", "Café ☕ 日本語"},
		{"emoji", "🦄🦄"},
		{"slash", "a/b"},
	} {
		ser("content: "+c.name, pub, 1, nil, c.s)
		ser("tag: "+c.name, pub, 1, [][]string{{"t", c.s}}, "")
	}

	add := func(name string, ev nip01.Event) {
		err := ev.Verify()
		f.Verify = append(f.Verify, verifyEventCase{Name: name, Event: ev, Valid: err == nil, Error: errString(err)})
	}
	sign := func(kind int, tags [][]string, content string) nip01.Event {
		ev := nip01.Event{CreatedAt: evTime, Kind: kind, Tags: tags, Content: content}
		if err := ev.Sign(evSecret); err != nil {
			panic(err)
		}
		return ev
	}
	good := sign(23198, [][]string{{"d", pub}, {"amount_millis", "21000"}}, "")
	add("signed claim proof", good)
	add("signed text note with escapes", sign(1, [][]string{{"t", "a b"}}, "line\none \"q\" \x01"))
	add("signed with nil tags", sign(1, nil, "x"))

	mut := func(name string, f func(*nip01.Event)) {
		ev := good
		ev.Tags = append([][]string{}, good.Tags...)
		f(&ev)
		add(name, ev)
	}
	mut("content changed after signing", func(e *nip01.Event) { e.Content = "x" })
	mut("tag changed after signing", func(e *nip01.Event) { e.Tags[1] = []string{"amount_millis", "21001"} })
	mut("created_at changed", func(e *nip01.Event) { e.CreatedAt++ })
	mut("signature flipped", func(e *nip01.Event) { e.Sig = flipHex(e.Sig) })
	mut("id flipped", func(e *nip01.Event) { e.ID = flipHex(e.ID) })
	mut("uppercase id", func(e *nip01.Event) { e.ID = strings.ToUpper(e.ID) })
	mut("uppercase pubkey", func(e *nip01.Event) { e.PubKey = strings.ToUpper(e.PubKey) })
	mut("uppercase signature", func(e *nip01.Event) { e.Sig = strings.ToUpper(e.Sig) })
	mut("short id", func(e *nip01.Event) { e.ID = e.ID[:62] })
	mut("non-hex id", func(e *nip01.Event) { e.ID = "zz" + e.ID[2:] })
	mut("short pubkey", func(e *nip01.Event) { e.PubKey = e.PubKey[:62] })
	mut("pubkey not on the curve", func(e *nip01.Event) { e.PubKey = strings.Repeat("ff", 32) })
	mut("short signature", func(e *nip01.Event) { e.Sig = e.Sig[:126] })
	mut("empty signature", func(e *nip01.Event) { e.Sig = "" })
	mut("kind -1", func(e *nip01.Event) { e.Kind = -1 })
	mut("kind 65536", func(e *nip01.Event) { e.Kind = 65536 })
	mut("signature from another key", func(e *nip01.Event) {
		other := nip01.Event{CreatedAt: e.CreatedAt, Kind: e.Kind, Tags: e.Tags, Content: e.Content}
		_ = other.Sign(strings.Repeat("02", 32))
		e.Sig = other.Sig
	})

	// NIP-13: a nonce tag makes Verify check the declared difficulty.
	evPub, err := utils.GetPublicKey(evSecret)
	if err != nil {
		return nil, err
	}
	mined := nip01.Event{CreatedAt: evTime, Kind: 1, Content: "pow", PubKey: evPub}
	if err := mined.Mine(context.Background(), 8); err != nil {
		return nil, err
	}
	if err := mined.Sign(evSecret); err != nil {
		return nil, err
	}
	add("nonce tag with enough work", mined)
	powSign := func(name string, nonce []string) {
		add(name, sign(1, [][]string{nonce}, "pow"))
	}
	powSign("nonce tag declaring more work than done", []string{"nonce", "1", "40"})
	powSign("nonce tag declaring zero", []string{"nonce", "1", "0"})
	powSign("nonce tag declaring a negative difficulty", []string{"nonce", "1", "-3"})
	powSign("nonce tag with a plus sign", []string{"nonce", "1", "+0"})
	powSign("nonce tag without a difficulty", []string{"nonce", "1"})
	powSign("nonce tag with a non-numeric difficulty", []string{"nonce", "1", "x"})
	add("two nonce tags", sign(1, [][]string{{"nonce", "1", "0"}, {"nonce", "2", "0"}}, "pow"))
	return f, nil
}

func flipHex(s string) string {
	b := []byte(s)
	if b[len(b)-1] == '0' {
		b[len(b)-1] = '1'
	} else {
		b[len(b)-1] = '0'
	}
	return string(b)
}
