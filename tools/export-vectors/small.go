package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
)

// ---- hub-group.json

type hubGroupFile struct {
	header
	HubGroupFor  []hubGroupForCase  `json:"hubGroupFor"`
	SameHubGroup []sameHubGroupCase `json:"sameHubGroup"`
}

// hubGroupForCase: HubGroupFor(Hub) == Group. NotRawBytes, when present, is
// what hashing the decoded 32 bytes would give instead; a port that
// produces it has fallen into the trap design §2.1 describes.
type hubGroupForCase struct {
	Hub         string `json:"hub"`
	Group       string `json:"group"`
	NotRawBytes string `json:"notRawBytes,omitempty"`
}

// sameHubGroupCase: SameHubGroup on two tokens whose hub groups are A and B
// (hex, null = absent).
type sameHubGroupCase struct {
	Name string  `json:"name"`
	A    *string `json:"a"`
	B    *string `json:"b"`
	Same bool    `json:"same"`
}

func buildHubGroup() (any, error) {
	f := hubGroupFile{header: newHeader(
		"Hub-group fingerprint: the first 4 bytes of sha256 over the hub pubkey's hex TEXT, and the grouping rule.",
		"nipcash/token.go HubGroupFor, SameHubGroup; nipcash/hub_group_test.go",
	)}
	pubkeys := []string{
		strings.Repeat("cd", 32),
		"4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
		strings.ToUpper("4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"),
	}
	for _, pk := range pubkeys {
		raw, _ := hex.DecodeString(pk)
		sum := sha256.Sum256(raw)
		f.HubGroupFor = append(f.HubGroupFor, hubGroupForCase{
			Hub:         pk,
			Group:       hex.EncodeToString(nipcash.HubGroupFor(pk)),
			NotRawBytes: hex.EncodeToString(sum[:nipcash.HubGroupLen]),
		})
	}
	for _, s := range []string{"hub-pubkey-aaa", "hub-a", "hub-b", ""} {
		f.HubGroupFor = append(f.HubGroupFor, hubGroupForCase{Hub: s, Group: hex.EncodeToString(nipcash.HubGroupFor(s))})
	}

	ga := hex.EncodeToString(nipcash.HubGroupFor("hub-a"))
	gb := hex.EncodeToString(nipcash.HubGroupFor("hub-b"))
	for _, c := range []struct {
		name string
		a, b *string
	}{
		{"same group", &ga, &ga},
		{"different groups", &ga, &gb},
		{"both absent is not a wildcard", nil, nil},
		{"one absent", &ga, nil},
		{"other absent", nil, &ga},
		{"wrong length on both", strPtr("0102"), strPtr("0102")},
		{"empty on both", strPtr(""), strPtr("")},
	} {
		tok := func(g *string) nipcash.Token {
			if g == nil {
				return nipcash.Token{}
			}
			b, _ := hex.DecodeString(*g)
			if b == nil {
				b = []byte{}
			}
			return nipcash.Token{HubGroup: b}
		}
		f.SameHubGroup = append(f.SameHubGroup, sameHubGroupCase{c.name, c.a, c.b, nipcash.SameHubGroup(tok(c.a), tok(c.b))})
	}
	return f, nil
}

// ---- cash-string.json

type cashStringFile struct {
	header
	Split []splitCase `json:"split"`
}

type splitCase struct {
	Input      string `json:"input"`
	Token      string `json:"token"`
	CashSecret string `json:"cashSecret"`
}

func buildCashString() (any, error) {
	f := cashStringFile{header: newHeader(
		"<token>#<cash_secret>: split on the first '#'.",
		"nipcash/cash_string.go SplitCashSliceString; nipcash/cash_string_test.go",
	)}
	for _, in := range []string{
		"lokicash1abc",
		"lokicash1abc#deadbeef",
		"lokicash1abc#dead#beef",
		"",
		"#",
		"#deadbeef",
		"lokicash1abc#",
		"lokicash1abc#" + strings.Repeat("ab", 32),
	} {
		tok, secret := nipcash.SplitCashSliceString(in)
		f.Split = append(f.Split, splitCase{in, tok, secret})
	}
	return f, nil
}

// ---- connection-key.json

type connectionKeyFile struct {
	header
	NewConnectionKey []newConnectionKeyCase `json:"newConnectionKey"`
	FromSecret       []fromSecretCase       `json:"fromSecret"`
}

// newConnectionKeyCase: the NIP-IC identity ConnectionKey,
// hex(sha256(platform ":" externalId)).
type newConnectionKeyCase struct {
	Platform   string `json:"platform"`
	ExternalID string `json:"externalId"`
	Key        string `json:"key"`
}

// fromSecretCase: the NIP-CW member connection key pair derived from a
// secret. Pubkey is the x-only (BIP-340 style) hex.
type fromSecretCase struct {
	Secret string `json:"secret"`
	Pubkey string `json:"pubkey,omitempty"`
	Error  string `json:"error,omitempty"`
}

func buildConnectionKey() (any, error) {
	f := connectionKeyFile{header: newHeader(
		"NIP-IC connection keys (platform identity hash) and NIP-CW member connection key pairs.",
		"nipIC/nipIC.go NewConnectionKey, nipcw/connection_key.go ConnectionKeyFromSecret; nipcash/kat_test.go, nipcw/connection_key_kat_test.go",
	)}
	for _, c := range [][2]string{
		{"github", "12345"},
		{"x", "alice"},
		{"telegram", ""},
		{"", "12345"},
		{"github", "a:b"},
		{"discord", "Ünïcødé"},
	} {
		f.NewConnectionKey = append(f.NewConnectionKey, newConnectionKeyCase{c[0], c[1], string(nipIC.NewConnectionKey(nipIC.WebIdentity(c[0]), c[1]))})
	}
	// Out-of-range secrets (zero, >= n) are left out on purpose: nmilat
	// reduces them mod n instead of refusing them, and cashkit refuses.
	for _, s := range []string{
		strings.Repeat("11", 32),
		strings.Repeat("00", 31) + "01",
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", // n-1
		strings.ToUpper(strings.Repeat("ab", 32)),
		strings.Repeat("11", 31),
		strings.Repeat("11", 33),
		"zz" + strings.Repeat("11", 31),
		"",
	} {
		k, err := nipcw.ConnectionKeyFromSecret(s)
		f.FromSecret = append(f.FromSecret, fromSecretCase{Secret: s, Pubkey: k.Pubkey(), Error: errString(err)})
	}
	return f, nil
}
