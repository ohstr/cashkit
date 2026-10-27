// Command export-vectors writes cashkit's conformance vectors (design §11.1)
// from nmilat's own vectors package: every expected value is computed by
// nmilat, the Go SDK cashkit ports, on fixed inputs. Nothing here
// re-implements protocol logic: if nmilat changes behaviour, `just vectors`
// changes the JSON and CI's drift check turns red until the TypeScript port
// follows.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ohstr/nmilat/vectors"
)

func main() {
	out := flag.String("out", "vectors", "directory to write the vector files into")
	flag.Parse()
	if err := vectors.WriteAll(*out); err != nil {
		fmt.Fprintln(os.Stderr, "export-vectors:", err)
		os.Exit(1)
	}
}
