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

package coalesced_forward_test

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// pipe is one side of a point-to-point link between two stacks. Packets
// written to it are delivered asynchronously, in order, to its peer. If
// coalesce is set, GSO packets are delivered whole, with GROSegmentSize set,
// like the host hands TSO/GRO packets to an AF_PACKET socket with a virtio-net
// header. A fraction of packets is dropped, and packets are dropped when the
// queue to the peer is full.
type pipe struct {
	*channel.Endpoint
	peer     *pipe
	coalesce bool
	dropRate float64
	q        chan *stack.PacketBuffer
	done     chan struct{}

	mu sync.Mutex
	// +checklocks:mu
	rnd *rand.Rand
	// +checklocks:mu
	closed bool
}

// newPipePair returns the two sides of a link with the given MTU. The first
// side coalesces the GSO packets written to it.

func newPipePair(mtu uint32, dropRate float64) (*pipe, *pipe) {
	mk := func(coalesce bool, seed int64) *pipe {
		p := &pipe{
			Endpoint: channel.New(0, mtu, ""),
			coalesce: coalesce,
			dropRate: dropRate,
			q:        make(chan *stack.PacketBuffer, 1024),
			done:     make(chan struct{}),
			rnd:      rand.New(rand.NewSource(seed)),
		}
		p.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
		if coalesce {
			// The sender side: lets TCP emit GSO packets.
			p.SupportedGSOKind = stack.HostGSOSupported
		}
		go func() {
			defer close(p.done)
			for pkt := range p.q {
				p.peer.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			}
		}()
		return p
	}
	a, b := mk(true, 1), mk(false, 2)
	a.peer, b.peer = b, a
	return a, b
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (p *pipe) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		n++
		p.mu.Lock()
		drop := p.closed || p.rnd.Float64() < p.dropRate
		p.mu.Unlock()
		if drop {
			continue
		}
		b := pkt.ToBuffer()
		v := b.Flatten()
		b.Release()
		if pkt.GSOOptions.NeedsCsum {
			// Complete the partial checksum, like the host would before
			// handing the packet over.
			ipH := header.IPv4(v)
			tcpH := header.TCP(ipH.Payload())
			xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ipH.SourceAddress(), ipH.DestinationAddress(), uint16(len(tcpH)))
			tcpH.SetChecksum(0)
			tcpH.SetChecksum(^tcpH.CalculateChecksum(checksum.Checksum(tcpH.Payload(), xsum)))
		}
		out := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(v)})
		if p.coalesce && pkt.GSOOptions.Type != stack.GSONone && pkt.Data().Size() > int(pkt.GSOOptions.MSS) {
			out.GROSegmentSize = pkt.GSOOptions.MSS
		}
		p.mu.Lock()
		if p.closed {
			out.DecRef()
		} else {
			select {
			case p.q <- out:
			default:
				out.DecRef()
			}
		}
		p.mu.Unlock()
	}
	return n, nil
}

// shutdown stops delivery to p's peer and waits for queued packets to be
// delivered.
func (p *pipe) shutdown() {
	p.mu.Lock()
	p.closed = true
	close(p.q)
	p.mu.Unlock()
	<-p.done
}

// newStack returns a stack with IPv4, ARP and TCP.
func newStack() *stack.Stack {
	return stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
}

// addAddr adds addr/24 to NIC nic of s.
func addAddr(t *testing.T, s *stack.Stack, nic tcpip.NICID, addr tcpip.Address) {
	t.Helper()
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24},
	}
	if err := s.AddProtocolAddress(nic, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(%d, %s): %s", nic, addr, err)
	}
}

var (
	senderAddr     = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	routerAddr1    = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	routerAddr2    = tcpip.AddrFrom4([4]byte{10, 0, 1, 1})
	receiverAddr   = tcpip.AddrFrom4([4]byte{10, 0, 1, 2})
	senderSubnet   = tcpip.AddressWithPrefix{Address: senderAddr, PrefixLen: 24}.Subnet()
	receiverSubnet = tcpip.AddressWithPrefix{Address: receiverAddr, PrefixLen: 24}.Subnet()
)

// TestCoalescedForwardingStress downloads concurrent TCP streams from a
// sender whose link coalesces segments, like a host with TSO/GRO, through a
// forwarding, masquerading stack onto a veth with a smaller MTU, to receivers
// that do not validate checksums, like containers behind a netstack bridge.
// Every byte received is checked.
//
// Packets are lost at random on the coalescing link, so TCP retransmits. The
// router itself must not drop any.
func TestCoalescedForwardingStress(t *testing.T) {
	const (
		flows    = 6
		size     = 4 << 20
		dropRate = 0.003
	)
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := t.Deadline(); ok && d.Before(deadline) {
		deadline = d.Add(-5 * time.Second)
	}

	sender, router, receiver := newStack(), newStack(), newStack()
	defer func() {
		for _, s := range []*stack.Stack{sender, router, receiver} {
			s.Close()
			s.Wait()
		}
	}()

	sEP, rIn := newPipePair(1500, dropRate)
	defer func() {
		sEP.shutdown()
		rIn.shutdown()
	}()
	rOut, recvEP := veth.NewPair(1486, 8192)
	for _, c := range []struct {
		s    *stack.Stack
		nic  tcpip.NICID
		name string
		ep   stack.LinkEndpoint
	}{{sender, 1, "eth0", sEP}, {router, 1, "eth0", rIn}, {router, 2, "docker0", rOut}, {receiver, 1, "eth0", recvEP}} {
		if err := c.s.CreateNICWithOptions(c.nic, c.ep, stack.NICOptions{Name: c.name}); err != nil {
			t.Fatalf("CreateNIC: %s", err)
		}
	}
	addAddr(t, sender, 1, senderAddr)
	addAddr(t, router, 1, routerAddr1)
	addAddr(t, router, 2, routerAddr2)
	addAddr(t, receiver, 1, receiverAddr)
	sender.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, Gateway: routerAddr1, NIC: 1}})
	receiver.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, Gateway: routerAddr2, NIC: 1}})
	router.SetRouteTable([]tcpip.Route{{Destination: senderSubnet, NIC: 1}, {Destination: receiverSubnet, NIC: 2}})
	if err := router.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("SetForwarding: %s", err)
	}
	// Masquerade connections from the receiver side out of eth0, like
	// Docker-in-gVisor's SNAT rule: replies are un-NATed by conntrack before
	// they are forwarded.
	ipt := router.IPTables()
	table := ipt.GetTable(stack.NATID, false)
	ruleIdx := table.BuiltinChains[stack.Postrouting]
	table.Rules[ruleIdx].Filter = stack.IPHeaderFilter{Protocol: header.TCPProtocolNumber, CheckProtocol: true, OutputInterface: "eth0"}
	table.Rules[ruleIdx].Target = &stack.MasqueradeTarget{NetworkProtocol: ipv4.ProtocolNumber}
	table.Rules[ruleIdx+1].Target = &stack.AcceptTarget{}
	ipt.ForceReplaceTable(stack.NATID, table, false)
	l, err := gonet.ListenTCP(sender, tcpip.FullAddress{NIC: 1, Addr: senderAddr, Port: 9000}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}

	data := func(flow int) []byte {
		b := make([]byte, size)
		rand.New(rand.NewSource(int64(flow) + 100)).Read(b)
		return b
	}
	errs := make(chan error, 3*flows)
	// The data sender (the "internet" server) accepts connections, reads a
	// 1-byte flow ID, and sends that flow's data.
	var serverWG sync.WaitGroup
	serverWG.Add(1)
	go func() {
		defer serverWG.Done()
		for i := 0; i < flows; i++ {
			c, err := l.Accept()
			if err != nil {
				errs <- fmt.Errorf("server: accept: %v", err)
				return
			}
			serverWG.Add(1)
			go func() {
				defer serverWG.Done()
				defer c.Close()
				if err := c.SetDeadline(deadline); err != nil {
					errs <- fmt.Errorf("server: set deadline: %v", err)
					return
				}
				var id [1]byte
				if _, err := io.ReadFull(c, id[:]); err != nil {
					errs <- fmt.Errorf("server: read id: %v", err)
					return
				}
				if _, err := c.Write(data(int(id[0]))); err != nil {
					errs <- fmt.Errorf("server: flow %d: write: %v", id[0], err)
				}
			}()
		}
	}()
	// The receivers (containers behind the bridge) dial out and check
	// every byte.
	var wg sync.WaitGroup
	for f := 0; f < flows; f++ {
		wg.Add(1)
		go func(flow int) {
			defer wg.Done()
			c, err := gonet.DialTCP(receiver, tcpip.FullAddress{NIC: 1, Addr: senderAddr, Port: 9000}, ipv4.ProtocolNumber)
			if err != nil {
				errs <- fmt.Errorf("flow %d: dial: %v", flow, err)
				return
			}
			defer c.Close()
			if err := c.SetDeadline(deadline); err != nil {
				errs <- fmt.Errorf("flow %d: set deadline: %v", flow, err)
				return
			}
			if _, err := c.Write([]byte{byte(flow)}); err != nil {
				errs <- fmt.Errorf("flow %d: write id: %v", flow, err)
				return
			}
			want := data(flow)
			got := make([]byte, size)
			if _, err := io.ReadFull(c, got); err != nil {
				errs <- fmt.Errorf("flow %d: read: %v", flow, err)
				return
			}
			if !bytes.Equal(got, want) {
				off := 0
				for off < size && got[off] == want[off] {
					off++
				}
				end := off
				for end < size && got[end] != want[end] {
					end++
				}
				errs <- fmt.Errorf("flow %d: corrupt payload at offset %d (%d bytes differ in first run; got %x want %x)", flow, off, end-off, got[off:min(off+16, size)], want[off:min(off+16, size)])
			}
		}(f)
	}
	wg.Wait()
	l.Close()
	serverWG.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if got := router.Stats().IP.Forwarding.Errors.Value(); got != 0 {
		t.Errorf("got router.Stats().IP.Forwarding.Errors.Value() = %d, want = 0", got)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
