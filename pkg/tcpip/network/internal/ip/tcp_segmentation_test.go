// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ip

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestHasSignatureOption(t *testing.T) {
	// NOP, NOP, timestamps: the usual layout.
	ts := []byte{header.TCPOptionNOP, header.TCPOptionNOP, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	header.EncodeTSOption(1, 2, ts[2:])
	md5 := append([]byte{header.TCPOptionNOP, header.TCPOptionNOP, tcpOptionMD5, 18}, make([]byte, 16)...)
	ao := append([]byte{tcpOptionAO, 16, 1, 2}, make([]byte, 12)...)
	for _, test := range []struct {
		name string
		opts []byte
		want bool
	}{
		{name: "none", opts: nil, want: false},
		{name: "timestamps", opts: ts, want: false},
		{name: "MD5", opts: md5, want: true},
		{name: "timestamps and MD5", opts: append(append([]byte(nil), ts...), md5...), want: true},
		{name: "AO", opts: ao, want: true},
		{name: "MD5 after EOL is ignored", opts: []byte{header.TCPOptionEOL, 0, tcpOptionMD5, 18}, want: false},
		{name: "truncated option", opts: []byte{header.TCPOptionNOP, header.TCPOptionMSS}, want: true},
		{name: "zero-length option", opts: []byte{header.TCPOptionMSS, 0, 0, 0}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := hasSignatureOption(test.opts); got != test.want {
				t.Errorf("hasSignatureOption(%x) = %t, want %t", test.opts, got, test.want)
			}
		})
	}
}
