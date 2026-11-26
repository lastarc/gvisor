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
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// PrepareTransportChecksumForFragmentation calculates the TCP or UDP checksum
// of pkt, which r sends in fragments, if the checksum can be incomplete. The
// checksum can be incomplete if r does not require transport checksums, and
// pkt is from a local transport endpoint or is a forwarded datagram that
// arrived on a link with RX checksum offload. A receiver can validate the
// checksum only after reassembly, so the fragments must carry the complete
// checksum.
func PrepareTransportChecksumForFragmentation(r *stack.Route, pkt *stack.PacketBuffer) {
	if r.RequiresTXTransportChecksum() {
		return
	}
	if pkt.NetworkPacketInfo.IsForwardedPacket {
		// A forwarded datagram from a sender on a link with TX checksum
		// offload has an incomplete checksum. A forwarded fragment has only a
		// part of the datagram, so its checksum stays as it is.
		if !pkt.RXChecksumValidated || IsIPv4Fragment(pkt) {
			return
		}
	} else if len(pkt.TransportHeader().Slice()) == 0 {
		// A packet from a raw endpoint keeps the checksum that the endpoint
		// wrote.
		return
	}
	pkt.CalculateTransportChecksum()
}

// IsIPv4Fragment returns true if pkt is an IPv4 fragment.
func IsIPv4Fragment(pkt *stack.PacketBuffer) bool {
	if pkt.NetworkProtocolNumber != header.IPv4ProtocolNumber {
		return false
	}
	h := header.IPv4(pkt.NetworkHeader().Slice())
	return h.More() || h.FragmentOffset() != 0
}
