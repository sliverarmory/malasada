package aplib

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestPackSafe_RoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("hello"),
		bytes.Repeat([]byte{0}, 4096),
		bytes.Repeat([]byte("ABCD"), 2048),
	}

	r := rand.New(rand.NewSource(1337))
	buf := make([]byte, 64*1024)
	if _, err := r.Read(buf); err != nil {
		t.Fatalf("rand read: %v", err)
	}
	cases = append(cases, buf)

	for i, tc := range cases {
		packed, err := PackSafe(tc)
		if err != nil {
			t.Fatalf("case %d: pack: %v", i, err)
		}
		got, err := DepackSafe(packed)
		if err != nil {
			t.Fatalf("case %d: depack: %v", i, err)
		}
		if !bytes.Equal(got, tc) {
			t.Fatalf("case %d: round-trip mismatch", i)
		}
	}
}
