module github.com/ohstr/cashkit/tools/export-vectors

go 1.26.10

// The vectors package ships from nmilat's next release; until it is tagged,
// a local, uncommitted go.work points this module at an nmilat checkout that
// has it (see the justfile's `vectors` recipe).
require github.com/ohstr/nmilat v0.5.0-rc.31
