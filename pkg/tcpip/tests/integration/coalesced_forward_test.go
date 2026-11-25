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
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/nested"
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
// queue to the peer is full. If clearDF is set, packets are delivered without
// the IPv4 Don't Fragment flag.
type pipe struct {
	*channel.Endpoint
	peer     *pipe
	coalesce bool
	clearDF  bool
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
		if p.clearDF {
			ipH := header.IPv4(v)
			ipH.SetFlagsFragmentOffset(ipH.Flags()&^header.IPv4FlagDontFragment, 0)
			ipH.SetChecksum(0)
			ipH.SetChecksum(^ipH.CalculateChecksum())
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

// fragmentCounter is a link endpoint that counts the IPv4 fragments that it
// delivers.
type fragmentCounter struct {
	nested.Endpoint
	fragments atomic.Int64
}

// newFragmentCounter returns a fragmentCounter that wraps ep.
func newFragmentCounter(ep stack.LinkEndpoint) *fragmentCounter {
	c := &fragmentCounter{}
	c.Endpoint.Init(ep, c)
	return c
}

// DeliverNetworkPacket implements stack.NetworkDispatcher.DeliverNetworkPacket.
func (c *fragmentCounter) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	if protocol == header.IPv4ProtocolNumber {
		if b, ok := pkt.Data().PullUp(header.IPv4MinimumSize); ok {
			if h := header.IPv4(b); h.Flags()&header.IPv4FlagMoreFragments != 0 || h.FragmentOffset() != 0 {
				c.fragments.Add(1)
			}
		}
	}
	c.Endpoint.DeliverNetworkPacket(protocol, pkt)
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
// forwarding, masquerading stack, to receivers that do not validate checksums,
// like containers behind a netstack bridge. Every byte received is checked.
//
// Packets are lost at random on the coalescing link, so TCP retransmits. The
// router itself must not drop any, and the receiver must not get IP
// fragments.
func TestCoalescedForwardingStress(t *testing.T) {
	// All variants share one deadline, which ends before the test's.
	deadline := time.Now().Add(40 * time.Second)
	if d, ok := t.Deadline(); ok && d.Add(-5*time.Second).Before(deadline) {
		deadline = d.Add(-5 * time.Second)
	}
	for _, test := range []coalescedForwardingTest{
		{name: "veth"},
		{name: "bridge", bridge: true},
		{name: "bridge without DF", bridge: true, clearDF: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runCoalescedForwardingStress(t, test, deadline)
		})
	}
}

// coalescedForwardingTest is a variant of TestCoalescedForwardingStress.
type coalescedForwardingTest struct {
	name string
	// bridge is whether the router reaches the receiver through a netstack
	// bridge, as Docker's default network in gVisor does, rather than
	// directly through a veth whose MTU is smaller than the sender's link.
	bridge bool
	// clearDF is whether the sender's packets arrive without the Don't
	// Fragment flag, so that the router fragments packets that are too
	// large for the outgoing link instead of dropping them.
	clearDF bool
}

// runCoalescedForwardingStress runs one variant of
// TestCoalescedForwardingStress. Connections time out at deadline.
func runCoalescedForwardingStress(t *testing.T, test coalescedForwardingTest, deadline time.Time) {
	const (
		flows    = 6
		size     = 4 << 20
		dropRate = 0.003
	)

	sender, router, receiver := newStack(), newStack(), newStack()
	defer func() {
		for _, s := range []*stack.Stack{sender, router, receiver} {
			s.Close()
			s.Wait()
		}
	}()

	linkMTU := uint32(1500)
	if test.bridge {
		// With MTU 1528 on the sender's link and on the veth, the sender
		// sends 1500-byte packets, which fill the bridge's MTU of 1500 as a
		// Linux sender fills the MSS of a 1500-byte link. A netstack sender
		// keeps 40 bytes of the MSS for TCP options, of which it uses 12
		// (timestamps).
		linkMTU = 1528
	}
	sEP, rIn := newPipePair(linkMTU, dropRate)
	sEP.clearDF = test.clearDF
	defer func() {
		sEP.shutdown()
		rIn.shutdown()
	}()
	type nic struct {
		s    *stack.Stack
		id   tcpip.NICID
		name string
		ep   stack.LinkEndpoint
	}
	nics := []nic{{sender, 1, "eth0", sEP}, {router, 1, "eth0", rIn}}
	var recvEP *fragmentCounter
	if test.bridge {
		rOut, rPeer := veth.NewPair(linkMTU, 8192)
		recvEP = newFragmentCounter(ethernet.NewWithNetworkMTU(rPeer))
		nics = append(nics,
			nic{router, 2, "docker0", stack.NewBridgeEndpoint(1500)},
			nic{router, 3, "veth0", ethernet.NewWithNetworkMTU(rOut)},
			nic{receiver, 1, "eth0", recvEP})
	} else {
		// The veth's MTU is smaller than the sender's link.
		rOut, rPeer := veth.NewPair(1486, 8192)
		recvEP = newFragmentCounter(rPeer)
		nics = append(nics, nic{router, 2, "veth0", rOut}, nic{receiver, 1, "eth0", recvEP})
	}
	for _, c := range nics {
		if err := c.s.CreateNICWithOptions(c.id, c.ep, stack.NICOptions{Name: c.name}); err != nil {
			t.Fatalf("CreateNIC: %s", err)
		}
	}
	if test.bridge {
		if err := router.SetNICCoordinator(3, 2); err != nil {
			t.Fatalf("SetNICCoordinator: %s", err)
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
	if got := recvEP.fragments.Load(); got != 0 {
		t.Errorf("receiver got %d IP fragments, want 0", got)
	}
}

func TestMain(m *testing.M) {
	// A veth delivers queued packets on a goroutine that Wait does not wait
	// for, so when the stacks stop while TCP retransmissions are in flight,
	// a few packet buffers can still be referenced at the leak check. Log
	// leaks rather than fail.
	refs.SetLeakMode(refs.LeaksLogWarning)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
