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

package fragmentation_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/pipe"
	"gvisor.dev/gvisor/pkg/tcpip/link/veth"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1
	mtu   = 1500
	port  = 9
)

func newStack(t *testing.T, ep stack.LinkEndpoint, addr tcpip.Address, proto tcpip.NetworkProtocolNumber) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("s.CreateNIC(%d, _): %s", nicID, err)
	}
	protocolAddr := tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: addr.WithPrefix()}
	if err := s.AddProtocolAddress(nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", nicID, protocolAddr, err)
	}
	subnet := tcpip.AddressWithPrefix{Address: addr, PrefixLen: addr.BitLen() - 8}.Subnet()
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: nicID}})
	return s
}

// TestFragmentedUDPOverChecksumOffloadLink tests that a UDP datagram that is
// larger than the MTU of a link with checksum offload arrives with a valid
// checksum after reassembly.
func TestFragmentedUDPOverChecksumOffloadLink(t *testing.T) {
	tests := []struct {
		name     string
		proto    tcpip.NetworkProtocolNumber
		src, dst tcpip.Address
	}{
		{
			name:  "IPv4",
			proto: ipv4.ProtocolNumber,
			src:   tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
			dst:   tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
		},
		{
			name:  "IPv6",
			proto: ipv6.ProtocolNumber,
			src:   tcpip.AddrFrom16([16]byte{0xfd, 15: 1}),
			dst:   tcpip.AddrFrom16([16]byte{0xfd, 15: 2}),
		},
	}
	for _, test := range tests {
		for _, size := range []int{mtu / 2, 4 * mtu} {
			t.Run(fmt.Sprintf("%s/%d", test.name, size), func(t *testing.T) {
				ep1, ep2 := veth.NewPair(mtu, veth.DefaultBacklogSize)
				s1 := newStack(t, ep1, test.src, test.proto)
				defer func() {
					s1.Close()
					s1.Wait()
				}()
				s2 := newStack(t, ep2, test.dst, test.proto)
				defer func() {
					s2.Close()
					s2.Wait()
				}()

				var rwq waiter.Queue
				rep, err := s2.NewEndpoint(udp.ProtocolNumber, test.proto, &rwq)
				if err != nil {
					t.Fatalf("s2.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, test.proto, err)
				}
				defer rep.Close()
				if err := rep.Bind(tcpip.FullAddress{Addr: test.dst, Port: port}); err != nil {
					t.Fatalf("rep.Bind(_): %s", err)
				}
				we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
				rwq.EventRegister(&we)
				defer rwq.EventUnregister(&we)

				var wwq waiter.Queue
				wep, err := s1.NewEndpoint(udp.ProtocolNumber, test.proto, &wwq)
				if err != nil {
					t.Fatalf("s1.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, test.proto, err)
				}
				defer wep.Close()
				data := bytes.Repeat([]byte{'a'}, size)
				to := tcpip.FullAddress{Addr: test.dst, Port: port, NIC: nicID}
				if _, err := wep.Write(bytes.NewReader(data), tcpip.WriteOptions{To: &to}); err != nil {
					t.Fatalf("wep.Write(_, {To: %+v}): %s", to, err)
				}

				select {
				case <-ch:
				case <-time.After(10 * time.Second):
					t.Fatalf("datagram of %d bytes not received; checksum errors: %d", size, s2.Stats().UDP.ChecksumErrors.Value())
				}
				var buf bytes.Buffer
				if _, err := rep.Read(&buf, tcpip.ReadOptions{}); err != nil {
					t.Fatalf("rep.Read(_, {}): %s", err)
				}
				if !bytes.Equal(buf.Bytes(), data) {
					t.Errorf("got %d bytes, want %d bytes of %q", buf.Len(), size, data[0])
				}
			})
		}
	}
}

// TestForwardedTCPFragmentedByRouter tests that TCP segments that a router
// forwards from a link with checksum offload, and sends in fragments, arrive
// with valid checksums after reassembly.
func TestForwardedTCPFragmentedByRouter(t *testing.T) {
	newStack := func() *stack.Stack {
		return stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		})
	}
	addNIC := func(s *stack.Stack, id tcpip.NICID, ep stack.LinkEndpoint, addr tcpip.Address) {
		t.Helper()
		if err := s.CreateNIC(id, ep); err != nil {
			t.Fatalf("s.CreateNIC(%d, _): %s", id, err)
		}
		protocolAddr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24}}
		if err := s.AddProtocolAddress(id, protocolAddr, stack.AddressProperties{}); err != nil {
			t.Fatalf("s.AddProtocolAddress(%d, %+v, {}): %s", id, protocolAddr, err)
		}
	}
	var (
		aAddr  = tcpip.AddrFrom4([4]byte{10, 0, 1, 1})
		r1Addr = tcpip.AddrFrom4([4]byte{10, 0, 1, 2})
		r2Addr = tcpip.AddrFrom4([4]byte{10, 0, 2, 1})
		bAddr  = tcpip.AddrFrom4([4]byte{10, 0, 2, 2})
	)
	// The router sends to B through a link with a smaller MTU.
	a1, r1 := veth.NewPair(mtu, veth.DefaultBacklogSize)
	r2, b2 := veth.NewPair(mtu, veth.DefaultBacklogSize)
	r2.SetMTU(1000)
	a, r, b := newStack(), newStack(), newStack()
	for _, s := range []*stack.Stack{a, r, b} {
		defer func(s *stack.Stack) {
			s.Close()
			s.Wait()
		}(s)
	}
	addNIC(a, 1, a1, aAddr)
	addNIC(r, 1, r1, r1Addr)
	addNIC(r, 2, r2, r2Addr)
	addNIC(b, 1, b2, bAddr)
	a.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1, Gateway: r1Addr}})
	b.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1, Gateway: r2Addr}})
	r.SetRouteTable([]tcpip.Route{
		{Destination: tcpip.AddressWithPrefix{Address: r1Addr, PrefixLen: 24}.Subnet(), NIC: 1},
		{Destination: tcpip.AddressWithPrefix{Address: r2Addr, PrefixLen: 24}.Subnet(), NIC: 2},
	})
	if err := r.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("r.SetForwardingDefaultAndAllNICs(%d, true): %s", ipv4.ProtocolNumber, err)
	}

	serverAddr := tcpip.FullAddress{Addr: bAddr, Port: 80}
	l, err := gonet.ListenTCP(b, serverAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.ListenTCP(_, %+v, %d): %s", serverAddr, ipv4.ProtocolNumber, err)
	}
	defer l.Close()
	received := make(chan int64, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			received <- -1
			return
		}
		defer c.Close()
		n, _ := io.Copy(io.Discard, c)
		received <- n
	}()

	var wq waiter.Queue
	ep, tcpErr := a.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		t.Fatalf("a.NewEndpoint(%d, %d, _): %s", tcp.ProtocolNumber, ipv4.ProtocolNumber, tcpErr)
	}
	// Do not set DF, so that the router fragments the segments.
	if err := ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont)); err != nil {
		t.Fatalf("ep.SetSockOptInt(MTUDiscoverOption, PMTUDiscoveryDont): %s", err)
	}
	we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)
	if err := ep.Connect(serverAddr); err != nil {
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			t.Fatalf("ep.Connect(%+v): %s", serverAddr, err)
		}
		<-ch
	}
	c := gonet.NewTCPConn(&wq, ep)
	data := bytes.Repeat([]byte{'a'}, 20000)
	if err := c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("c.SetWriteDeadline(_): %s", err)
	}
	if _, err := c.Write(data); err != nil {
		t.Fatalf("c.Write(_): %s; checksum errors: %d", err, b.Stats().TCP.ChecksumErrors.Value())
	}
	c.Close()
	select {
	case n := <-received:
		if n != int64(len(data)) {
			t.Errorf("got %d bytes, want %d; checksum errors: %d", n, len(data), b.Stats().TCP.ChecksumErrors.Value())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("data not received; checksum errors: %d", b.Stats().TCP.ChecksumErrors.Value())
	}
	if got := r.Stats().IP.PacketsSent.Value(); got == 0 {
		t.Errorf("got router PacketsSent = 0, want > 0")
	}
}

// TestForwardedUDPFragmentsKeepChecksum tests that a router that forwards
// fragments of a UDP datagram to a link that requires transport checksums
// does not change the checksum in the first fragment.
func TestForwardedUDPFragmentsKeepChecksum(t *testing.T) {
	var (
		aAddr  = tcpip.AddrFrom4([4]byte{10, 0, 1, 1})
		r1Addr = tcpip.AddrFrom4([4]byte{10, 0, 1, 2})
		r2Addr = tcpip.AddrFrom4([4]byte{10, 0, 2, 1})
		bAddr  = tcpip.AddrFrom4([4]byte{10, 0, 2, 2})
	)
	// The link from A to the router has checksum offload. The link from the
	// router to B does not, and has the same MTU, so the router forwards the
	// fragments that A sends without a change.
	a1, r1 := veth.NewPair(mtu, veth.DefaultBacklogSize)
	r2, b2 := pipe.New("", "", mtu)
	a := newStack(t, a1, aAddr, ipv4.ProtocolNumber)
	b := newStack(t, b2, bAddr, ipv4.ProtocolNumber)
	r := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
	})
	for _, s := range []*stack.Stack{a, r, b} {
		defer func(s *stack.Stack) {
			s.Close()
			s.Wait()
		}(s)
	}
	for _, nic := range []struct {
		id   tcpip.NICID
		ep   stack.LinkEndpoint
		addr tcpip.Address
	}{{1, r1, r1Addr}, {2, r2, r2Addr}} {
		if err := r.CreateNIC(nic.id, nic.ep); err != nil {
			t.Fatalf("r.CreateNIC(%d, _): %s", nic.id, err)
		}
		protocolAddr := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: nic.addr, PrefixLen: 24}}
		if err := r.AddProtocolAddress(nic.id, protocolAddr, stack.AddressProperties{}); err != nil {
			t.Fatalf("r.AddProtocolAddress(%d, %+v, {}): %s", nic.id, protocolAddr, err)
		}
	}
	a.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID, Gateway: r1Addr}})
	b.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID, Gateway: r2Addr}})
	r.SetRouteTable([]tcpip.Route{
		{Destination: tcpip.AddressWithPrefix{Address: r1Addr, PrefixLen: 24}.Subnet(), NIC: 1},
		{Destination: tcpip.AddressWithPrefix{Address: r2Addr, PrefixLen: 24}.Subnet(), NIC: 2},
	})
	if err := r.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("r.SetForwardingDefaultAndAllNICs(%d, true): %s", ipv4.ProtocolNumber, err)
	}

	var rwq waiter.Queue
	rep, err := b.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &rwq)
	if err != nil {
		t.Fatalf("b.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, ipv4.ProtocolNumber, err)
	}
	defer rep.Close()
	if err := rep.Bind(tcpip.FullAddress{Addr: bAddr, Port: port}); err != nil {
		t.Fatalf("rep.Bind(_): %s", err)
	}
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	rwq.EventRegister(&we)
	defer rwq.EventUnregister(&we)

	var wwq waiter.Queue
	wep, err := a.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wwq)
	if err != nil {
		t.Fatalf("a.NewEndpoint(%d, %d, _): %s", udp.ProtocolNumber, ipv4.ProtocolNumber, err)
	}
	defer wep.Close()
	data := bytes.Repeat([]byte{'a'}, 4*mtu)
	to := tcpip.FullAddress{Addr: bAddr, Port: port}
	if _, err := wep.Write(bytes.NewReader(data), tcpip.WriteOptions{To: &to}); err != nil {
		t.Fatalf("wep.Write(_, {To: %+v}): %s", to, err)
	}

	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("datagram not received; checksum errors: %d", b.Stats().UDP.ChecksumErrors.Value())
	}
	var buf bytes.Buffer
	if _, err := rep.Read(&buf, tcpip.ReadOptions{}); err != nil {
		t.Fatalf("rep.Read(_, {}): %s", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Errorf("got %d bytes, want %d bytes of %q", buf.Len(), len(data), data[0])
	}
	if got := r.Stats().IP.PacketsSent.Value(); got < 2 {
		t.Errorf("got router PacketsSent = %d, want >= 2", got)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
