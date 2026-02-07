package malasada

import (
	"encoding/hex"
	"testing"
)

func TestStubs_GoldenBytes(t *testing.T) {
	const (
		stubVaddr   = 0x400000
		exportVaddr = 0x123456
		initVaddr   = 0x5678
	)

	gotAMD64, err := makeStubAMD64(stubVaddr, exportVaddr, []uint64{initVaddr, 0})
	if err != nil {
		t.Fatalf("makeStubAMD64: %v", err)
	}
	wantAMD64 := "e8000000005b4881eb050040004989e74d8b274d8d6f084c89e14883c10248c1e1034d8d340f4c89e74c89ee4c89f248b878560000000000004801d8ffd048b856341200000000004801d8ffd0b8e700000031ff0f05"
	if got := hex.EncodeToString(gotAMD64); got != wantAMD64 {
		t.Fatalf("amd64 stub mismatch:\nwant %s\ngot  %s", wantAMD64, got)
	}

	gotARM64, err := makeStubARM64(stubVaddr, exportVaddr, []uint64{initVaddr, 0})
	if err != nil {
		t.Fatalf("makeStubARM64: %v", err)
	}
	wantARM64 := "13000010140080d21408a0f21400c0f21400e0f2730214cbf50340f9f6230091d70e158bf7220091e00315aae10316aae20317aa14cf8ad21400a0f21400c0f21400e0f27002148b00023fd6d48a86d25402a0f21400c0f21400e0f27002148b00023fd6c80b80d2000080d2010000d4"
	if got := hex.EncodeToString(gotARM64); got != wantARM64 {
		t.Fatalf("arm64 stub mismatch:\nwant %s\ngot  %s", wantARM64, got)
	}
}
