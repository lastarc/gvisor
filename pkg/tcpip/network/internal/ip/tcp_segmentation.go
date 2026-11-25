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
	"math"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// tcpHeaderBuf holds a copy of a TCP header.
type tcpHeaderBuf struct {
	buf [header.TCPHeaderMaximumSize]byte
	len int
}

// tcp returns the TCP header held by b.
func (b *tcpHeaderBuf) tcp() header.TCP {
	return header.TCP(b.buf[:b.len])
}

// forwardedTCPHeader copies the TCP header of pkt, an IP packet whose network
// header of netHdrLen bytes is populated and whose transport protocol is TCP,
// to hdr. It returns the number of TCP payload bytes that follow the header.
//
// It does not modify pkt's buffer.
func forwardedTCPHeader(pkt *stack.PacketBuffer, netHdrLen int, hdr *tcpHeaderBuf) (int, bool) {
	buf := stack.BufferSince(pkt.NetworkHeader())
	defer buf.Release()
	tcpLen := int(buf.Size()) - netHdrLen
	if tcpLen < header.TCPMinimumSize {
		return 0, false
	}
	if n, _ := buf.ReadAt(hdr.buf[:header.TCPMinimumSize], int64(netHdrLen)); n != header.TCPMinimumSize {
		return 0, false
	}
	hdrLen := int(header.TCP(hdr.buf[:]).DataOffset())
	if hdrLen < header.TCPMinimumSize || hdrLen > tcpLen {
		return 0, false
	}
	if n, _ := buf.ReadAt(hdr.buf[header.TCPMinimumSize:hdrLen], int64(netHdrLen+header.TCPMinimumSize)); n != hdrLen-header.TCPMinimumSize {
		return 0, false
	}
	hdr.len = hdrLen
	return tcpLen - hdrLen, true
}

// ForwardedTCPSegmentSize returns the TCP payload size into which pkt, a TCP
// packet about to be forwarded through a link with MTU egressMTU, may be
// resegmented if it does not fit, or zero if it should be treated like any
// other packet.
//
// pkt may carry several on-the-wire TCP segments if it was coalesced by GRO,
// either in gVisor or by the host (e.g. a TSO/GSO packet received from a veth
// whose peer offloads segmentation). Linux forwards such packets as long as
// the original segments fit the egress MTU (see skb_gso_validate_network_len)
// and resegments them on transmit; netstack mirrors that by resegmenting in
// software when writing the packet.
//
// When the segment size is known (pkt.GROSegmentSize), it is returned as-is so
// that the egress path can still reject the packet with an ICMP "fragmentation
// needed"/"packet too big" error if the original segments do not fit, which
// lets the sender's path MTU discovery converge. A known size is only trusted
// if it is plausible and a segment of that size could have crossed the ingress
// link: e.g. netstack GRO records the payload size of the first packet it
// merges, which may itself be a super-frame coalesced by the host.
//
// Otherwise, if a size was recorded but is not credible, or if the packet is
// larger than the ingress link MTU and so can only have been coalesced below
// netstack, the original segment boundaries are lost. The payload is then
// split into the fewest equally sized segments that fit both the ingress and
// egress links. Rejecting the packet would not help, as lowering the sender's
// MSS cannot shrink a coalesced packet. Splitting evenly reproduces the
// sender's segmentation when the packet holds a few full-sized segments, but
// in general segments may be larger than the sender's, so links that can
// coalesce should report the segment size (fdbased does so whenever the host
// supports virtio-net headers on its AF_PACKET socket).
//
// A packet with no recorded segment size that fits the ingress link may be a
// single segment, and is treated like any other packet.
//
// netHdrLen and totalLen are the lengths of pkt's network header and of the
// whole IP packet, which the caller has already parsed.
func ForwardedTCPSegmentSize(pkt *stack.PacketBuffer, netHdrLen, totalLen int, ingressMTU, egressMTU uint32) uint16 {
	if uint32(totalLen) <= egressMTU || (pkt.GROSegmentSize == 0 && uint32(totalLen) <= ingressMTU) {
		// The packet fits the egress link, the common case, or may be a single
		// segment. Avoid parsing the TCP header.
		return 0
	}
	var tcpHdr tcpHeaderBuf
	payloadLen, ok := forwardedTCPHeader(pkt, netHdrLen, &tcpHdr)
	if !ok {
		return 0
	}
	hdrLen := netHdrLen + tcpHdr.len
	if gro := int(pkt.GROSegmentSize); gro >= minSegmentSize && uint32(hdrLen+gro) <= ingressMTU {
		return pkt.GROSegmentSize
	}
	maxSize := int(min(ingressMTU, egressMTU)) - hdrLen
	if maxSize <= 0 {
		return 0
	}
	count := (payloadLen + maxSize - 1) / maxSize
	size := (payloadLen + count - 1) / count
	if size > math.MaxUint16 {
		return 0
	}
	return uint16(size)
}

// minSegmentSize is the smallest credible TCP segment size; smaller recorded
// segment sizes are treated as unknown. It matches the default of Linux's
// net.ipv4.tcp_min_snd_mss.
const minSegmentSize = 48

// CanSegmentTCP returns whether pkt, a forwarded IP packet with a network
// header of netHdrLen bytes carrying a TCP segment whose payload exceeds
// networkMTU (the MTU available to the network layer payload), can be sent by
// SegmentTCP in segments that each fit networkMTU.
func CanSegmentTCP(pkt *stack.PacketBuffer, netHdrLen int, networkMTU uint32) bool {
	mss := int(pkt.GROSegmentSize)
	if mss == 0 || !pkt.NetworkPacketInfo.IsForwardedPacket {
		return false
	}
	var hdr tcpHeaderBuf
	payloadLen, ok := forwardedTCPHeader(pkt, netHdrLen, &hdr)
	if !ok || payloadLen <= mss {
		return false
	}
	tcpHdr := hdr.tcp()
	// GRO never coalesces these; leave such packets alone.
	if tcpHdr.Flags()&(header.TCPFlagSyn|header.TCPFlagRst|header.TCPFlagUrg) != 0 {
		return false
	}
	// Neither are segments signed with TCP-MD5 or TCP-AO, whose signatures
	// would not match resegmented payloads.
	if hasSignatureOption(tcpHdr.Options()) {
		return false
	}
	return uint32(len(tcpHdr)+mss) <= networkMTU
}

// hasSignatureOption returns whether TCP options opts include a TCP-MD5
// (RFC 2385) or TCP-AO (RFC 5925) option.
func hasSignatureOption(opts []byte) bool {
	for i := 0; i < len(opts); {
		switch opts[i] {
		case header.TCPOptionEOL:
			return false
		case header.TCPOptionNOP:
			i++
			continue
		case tcpOptionMD5, tcpOptionAO:
			return true
		}
		if i+1 >= len(opts) || opts[i+1] < 2 {
			// Malformed; be conservative.
			return true
		}
		i += int(opts[i+1])
	}
	return false
}

const (
	tcpOptionMD5 = 19
	tcpOptionAO  = 29
)

// SegmentTCP splits pkt, a packet accepted by CanSegmentTCP, into TCP segments
// carrying at most pkt.GROSegmentSize bytes of payload each, as TCP
// segmentation offload would, and passes them to write in order.
//
// Each segment carries a copy of pkt's network and TCP headers, with the
// sequence number advanced, PSH and FIN set only on the last segment, CWR set
// only on the first, and a freshly computed TCP checksum (pkt's checksum may
// be partial if it was produced by the host's GSO). fixNetworkHeader is called
// with each segment's network header in place and must update its length,
// and for IPv4 its identification and checksum; it returns the TCP
// pseudo-header checksum for the segment, whose TCP length is given.
//
// netHdr is pkt's network header. reserve is the number of bytes to reserve for link-layer headers.
//
// It returns the number of segments written, the number that were not, and
// the error that stopped it, if any.
func SegmentTCP(pkt *stack.PacketBuffer, netHdr []byte, reserve int, fixNetworkHeader func(seg *stack.PacketBuffer, index int, tcpLen uint16) uint16, write func(*stack.PacketBuffer) tcpip.Error) (int, int, tcpip.Error) {
	var hdr tcpHeaderBuf
	payloadLen, ok := forwardedTCPHeader(pkt, len(netHdr), &hdr)
	tcpHdr := hdr.tcp()
	if !ok {
		return 0, 1, &tcpip.ErrMalformedHeader{}
	}
	mss := int(pkt.GROSegmentSize)
	count := (payloadLen + mss - 1) / mss

	data := stack.BufferSince(pkt.NetworkHeader())
	defer data.Release()
	data.TrimFront(int64(len(netHdr) + len(tcpHdr)))

	seq := tcpHdr.SequenceNumber()
	flags := tcpHdr.Flags()
	for i := 0; i < count; i++ {
		seg := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: reserve + len(netHdr) + len(tcpHdr),
			IsForwardedPacket:  true,
			Mark:               pkt.Mark,
		})
		n := seg.Data().ReadFrom(&data, mss)

		segTCP := header.TCP(seg.TransportHeader().Push(len(tcpHdr)))
		copy(segTCP, tcpHdr)
		seg.TransportProtocolNumber = header.TCPProtocolNumber
		segTCP.SetSequenceNumber(seq + uint32(i*mss))
		segFlags := flags
		if i != 0 {
			segFlags &^= header.TCPFlagCwr
		}
		if i != count-1 {
			segFlags &^= header.TCPFlagFin | header.TCPFlagPsh
		}
		segTCP.SetFlags(uint8(segFlags))

		copy(seg.NetworkHeader().Push(len(netHdr)), netHdr)
		seg.NetworkProtocolNumber = pkt.NetworkProtocolNumber
		seg.NICID = pkt.NICID
		seg.InputNICID = pkt.InputNICID

		tcpLen := uint16(len(tcpHdr) + n)
		xsum := fixNetworkHeader(seg, i, tcpLen)
		xsum = checksum.Combine(xsum, seg.Data().Checksum())
		segTCP.SetChecksum(0)
		segTCP.SetChecksum(^segTCP.CalculateChecksum(xsum))

		err := write(seg)
		seg.DecRef()
		if err != nil {
			return i, count - i, err
		}
	}
	return count, 0, nil
}
