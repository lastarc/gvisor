// Copyright 2022 The gVisor Authors.
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

package gro

import (
	"math/bits"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type countingDispatcher struct {
	delivered int
}

func (d *countingDispatcher) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
	d.delivered++
}

func (*countingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func TestNBuckets(t *testing.T) {
	// groNBuckets must be a power of 2 so that we can use groNBuckets-1 as
	// a mask when indexing into the list of buckets.
	if bits.OnesCount(groNBuckets) != 1 {
		t.Fatalf("groNBuckets is not a power of two")
	}
}

func TestFlushDrainsBucket(t *testing.T) {
	dispatcher := &countingDispatcher{}
	gd := GRO{Dispatcher: dispatcher}
	gd.Init(true)
	bucket := &gd.buckets[0]
	for i := 0; i < groBucketSize; i++ {
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{})
		bucket.insert(packet, nil, nil)
	}
	t.Cleanup(func() {
		for bucket.count != 0 {
			bucket.removeOldest().DecRef()
		}
	})

	gd.Flush()

	if got := dispatcher.delivered; got != groBucketSize {
		t.Errorf("Flush delivered %d packets, want %d", got, groBucketSize)
	}
	if got := bucket.count; got != 0 {
		t.Errorf("Flush left %d packets in bucket, want 0", got)
	}
}

type recordingDispatcher struct {
	pkts []*stack.PacketBuffer
}

func (d *recordingDispatcher) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.pkts = append(d.pkts, pkt.IncRef())
}

func (*recordingDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {
}

func newTCPv4Packet(seq uint32, payloadLen int) *stack.PacketBuffer {
	b := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+payloadLen)
	header.IPv4(b).Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		Protocol:    uint8(header.TCPProtocolNumber),
		TTL:         64,
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		DstAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
	})
	header.TCP(b[header.IPv4MinimumSize:]).Encode(&header.TCPFields{
		SrcPort:    80,
		DstPort:    1234,
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 65535,
	})
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.RXChecksumValidated = true
	return pkt
}

// TestNoMergeOfLargerSegment tests that a segment larger than the first one
// in a flow is not coalesced into it, so that GROSegmentSize never understates
// the size of the coalesced segments.
func TestNoMergeOfLargerSegment(t *testing.T) {
	dispatcher := &recordingDispatcher{}
	gd := GRO{Dispatcher: dispatcher}
	gd.Init(true)
	defer func() {
		for _, pkt := range dispatcher.pkts {
			pkt.DecRef()
		}
	}()

	// A short segment (e.g. the tail of a segment re-cut after an MSS
	// reduction) followed by two full ones.
	seq := uint32(1000)
	for _, size := range []int{14, 1434, 1434} {
		pkt := newTCPv4Packet(seq, size)
		gd.Enqueue(pkt)
		pkt.DecRef()
		seq += uint32(size)
	}
	gd.Flush()

	type result struct {
		payload        int
		groSegmentSize uint16
	}
	var got []result
	for _, pkt := range dispatcher.pkts {
		got = append(got, result{
			payload:        pkt.Data().Size() - header.IPv4MinimumSize - header.TCPMinimumSize,
			groSegmentSize: pkt.GROSegmentSize,
		})
	}
	want := []result{{payload: 14}, {payload: 2 * 1434, groSegmentSize: 1434}}
	if len(got) != len(want) {
		t.Fatalf("got delivered packets %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("packet %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
