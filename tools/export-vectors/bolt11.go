package main

import (
	"math/big"
	"strconv"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/ohstr/nmilat/nip57"
)

type bolt11File struct {
	header
	Decode []bolt11Case `json:"decode"`
}

// bolt11Case: nmilat's DecodeBolt11 either fails (Error) or yields the
// fields. AmountMillis is decimal (millis = nmilat's "mloki"). Overflow
// marks an amount nmilat computes with wrapping int64 arithmetic; cashkit
// refuses those, so Want is only meaningful when Overflow is false.
type bolt11Case struct {
	Name     string      `json:"name"`
	Invoice  string      `json:"invoice"`
	Error    string      `json:"error,omitempty"`
	Want     *bolt11JSON `json:"want,omitempty"`
	Overflow bool        `json:"overflow,omitempty"`
}

type bolt11JSON struct {
	Currency        string `json:"currency"`
	AmountMillis    string `json:"amountMillis"`
	Description     string `json:"description"`
	DescriptionHash string `json:"descriptionHash"`
	PaymentHash     string `json:"paymentHash"`
}

// field is one bolt11 tagged field, in 5-bit words.
type field struct {
	typ   byte
	words []byte
}

func hashField(typ byte, b []byte) field { return field{typ, words(b)} }

// invoice builds a structurally valid bolt11 string. The signature is
// zeros: nmilat never checks it.
func invoice(hrp string, fields ...field) string {
	w := make([]byte, 7) // timestamp
	for _, f := range fields {
		w = append(w, f.typ, byte(len(f.words)>>5), byte(len(f.words)&31))
		w = append(w, f.words...)
	}
	w = append(w, make([]byte, 104)...)
	return mustEncodeWords(hrp, w)
}

// exactMillis is the amount nmilat should compute, or nil if it does not
// fit int64, which nmilat silently wraps.
func exactMillis(amountPart string) *big.Int {
	if amountPart == "" {
		return big.NewInt(0)
	}
	mult := map[byte]int64{'m': 100_000_000, 'u': 100_000, 'n': 100, 'p': 1}
	last := amountPart[len(amountPart)-1]
	digits, factor := amountPart, int64(100_000_000_000)
	if f, ok := mult[last]; ok {
		digits, factor = amountPart[:len(amountPart)-1], f
	}
	v, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil
	}
	v.Mul(v, big.NewInt(factor))
	if last == 'p' {
		v.Div(v, big.NewInt(10))
	}
	if !v.IsInt64() {
		return nil
	}
	return v
}

func buildBolt11() (any, error) {
	f := bolt11File{header: newHeader(
		"bolt11 invoice fields nmilat reads: currency and amount from the HRP, payment hash, description and description hash. The signature is not checked.",
		"nip57/bolt11.go DecodeBolt11; real invoices from cashctl and nmilat test fixtures",
	)}
	ph := hashField(1, repeat(0xaa, 32))
	add := func(name, inv, _ string) {
		c := bolt11Case{Name: name, Invoice: inv}
		amountPart := amountPartOf(inv)
		got, err := nip57.DecodeBolt11(inv)
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Want = &bolt11JSON{got.Currency, strconv.FormatInt(got.AmountMloki, 10), got.Description, got.DescriptionHash, got.PaymentHash}
			if exact := exactMillis(amountPart); exact == nil || exact.Int64() != got.AmountMloki {
				c.Overflow = true
			}
		}
		f.Decode = append(f.Decode, c)
	}

	for _, c := range []struct{ name, inv, amount string }{
		{"real lnbc 10u", "lnbc10u1p3pj257pp5yztkwjcz5ftl5laxkav23zmzekaw37zk6kmv80pk4xaev5qhtz7qdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w", "10u"},
		{"real lnbc no amount (BOLT 11 example)", "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql", ""},
		{"real lnfc 10u", "lnfc10u1p4dqm55pp55aq08rgfwhrrdpy5z5jhyd0v2p6ddlurxzj6q6gdx0a5j7c5hnyqdqdw3exzmnnvejhycqzeqxqyz5vqrzjq0uu9vvap7vzzlt63829ht853lrzuzuxgw76qe7l6qf6u5fsm2qjlapyqqqqqqqq9cqqqqlgqqqqqeqpjqsp5uv65wj7xp88qlul2pk5uymnfq2wedpn3g4545mswfmj0df4pup7q9qxpqysgqnwdkm8xuwgq4cp5ukw4kfmz6pz0zcwxtr77n05ls0ljk2rsmg46rmfdnfycwl0p26dyk0ufvmtlyxejn9sm4jp2t8ua663qnufqyhxqplfddnp", "10u"},
	} {
		add(c.name, c.inv, c.amount)
	}

	for _, amt := range []string{"", "1", "25m", "10u", "2500n", "10p", "15p", "7x", "u", "0", "007u", "99999999999", "92233720368547758m", "9223372036854775807p", "99999999999999999999999u"} {
		add("amount "+strconv.Quote(amt), invoice("lnfc"+amt, ph), amt)
	}
	add("currency with a digit-free suffix", invoice("lnbcrt", ph), "")
	add("description and its hash", invoice("lnfc1u", ph, field{13, words([]byte("coffee ☕"))}, hashField(23, repeat(0xdd, 32))), "1u")
	add("unknown fields are skipped", invoice("lnfc1u", field{9, []byte{1, 2, 3}}, ph, field{31, nil}), "1u")
	add("last valid payment hash wins", invoice("lnfc1u", ph, hashField(1, repeat(0xbb, 32))), "1u")
	add("short payment hash is skipped", invoice("lnfc1u", field{1, words(repeat(0xaa, 31))}), "1u")
	add("short payment hash then a good one", invoice("lnfc1u", field{1, words(repeat(0xaa, 31))}, ph), "1u")
	add("payment hash with non-zero padding", invoice("lnfc1u", field{1, setLastBit(words(repeat(0xaa, 32)))}), "1u")
	add("description with bad padding is dropped", invoice("lnfc1u", ph, field{13, setLastBit(words([]byte("x")))}), "1u")
	add("no payment hash", invoice("lnfc1u", field{13, words([]byte("x"))}), "1u")
	add("truncated field", mustEncodeWords("lnfc1u", append(append(make([]byte, 7), 1, 1, 20, 0, 0), make([]byte, 104)...)), "1u")
	add("data shorter than timestamp and signature", mustEncodeWords("lnfc1u", make([]byte, 100)), "1u")
	add("not a lightning hrp", invoice("lokicash", ph), "")
	add("bad checksum", flipLastChar(invoice("lnfc1u", ph)), "1u")
	add("uppercase", toUpper(invoice("lnfc1u", ph)), "1u")
	return f, nil
}

// amountPartOf is the HRP's amount, located as nmilat does: from the first
// digit after "ln".
func amountPartOf(inv string) string {
	hrp, _, err := bech32.DecodeNoLimit(inv)
	if err != nil || len(hrp) < 2 {
		return ""
	}
	rest := hrp[2:]
	for i, c := range rest {
		if c >= '0' && c <= '9' {
			return rest[i:]
		}
	}
	return ""
}

func setLastBit(w []byte) []byte {
	out := append([]byte{}, w...)
	out[len(out)-1] |= 1
	return out
}

func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
