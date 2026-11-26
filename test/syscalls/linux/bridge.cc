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

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Linux network headers require <net/if.h> and <netinet/in.h> to precede them.
// clang-format off
#include <net/if.h>
#include <netinet/in.h>
// clang-format on

#include <linux/capability.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/veth.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "test/syscalls/linux/socket_netlink_route_util.h"
#include "test/syscalls/linux/socket_netlink_util.h"
#include "test/util/cleanup.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/logging.h"
#include "test/util/posix_error.h"
#include "test/util/save_util.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

using MacAddress = std::array<uint8_t, ETH_ALEN>;

constexpr uint32_t kSeq = 7000;
constexpr uint16_t kPort = 9000;
constexpr char kBridgeIP[] = "192.0.2.1";
constexpr char kPeerIP[] = "192.0.2.2";
constexpr MacAddress kBridgeMac = {0x02, 0x00, 0x00, 0x00, 0xb0, 0x01};
constexpr MacAddress kUnknownMac = {0x02, 0x00, 0x00, 0x00, 0xb0, 0x02};
constexpr MacAddress kNewPortAMac = {0x02, 0x00, 0x00, 0x00, 0xb0, 0x03};
constexpr MacAddress kNewPortBMac = {0x02, 0x00, 0x00, 0x00, 0xb0, 0x04};
constexpr MacAddress kBroadcastMac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
constexpr size_t kPayloadOffset =
    sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

struct LinkRequest {
  struct nlmsghdr hdr;
  struct ifinfomsg ifm;
  char buf[512];
};

struct rtattr* AddAttr(LinkRequest* req, int type, const void* data, int len) {
  struct rtattr* rta = reinterpret_cast<struct rtattr*>(
      reinterpret_cast<char*>(req) + NLMSG_ALIGN(req->hdr.nlmsg_len));
  TEST_CHECK(NLMSG_ALIGN(req->hdr.nlmsg_len) + RTA_SPACE(len) <= sizeof(*req));
  rta->rta_type = type;
  rta->rta_len = RTA_LENGTH(len);
  if (len > 0) {
    memcpy(RTA_DATA(rta), data, len);
  }
  req->hdr.nlmsg_len = NLMSG_ALIGN(req->hdr.nlmsg_len) + RTA_SPACE(len);
  return rta;
}

void EndNest(LinkRequest* req, struct rtattr* nest) {
  nest->rta_len = reinterpret_cast<char*>(req) + req->hdr.nlmsg_len -
                  reinterpret_cast<char*>(nest);
}

// Creates a link of the given kind. If peer is not null, the link is a veth
// pair and peer names the other end. If mtu is not 0, the link is created with
// that MTU.
PosixError NewLink(const FileDescriptor& fd, uint32_t seq, const char* kind,
                   const char* name, const char* peer, uint32_t mtu = 0) {
  LinkRequest req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifm));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
  req.hdr.nlmsg_seq = seq;
  AddAttr(&req, IFLA_IFNAME, name, strlen(name));
  if (mtu != 0) {
    AddAttr(&req, IFLA_MTU, &mtu, sizeof(mtu));
  }
  struct rtattr* linkinfo = AddAttr(&req, IFLA_LINKINFO, nullptr, 0);
  AddAttr(&req, IFLA_INFO_KIND, kind, strlen(kind));
  if (peer != nullptr) {
    struct rtattr* data = AddAttr(&req, IFLA_INFO_DATA, nullptr, 0);
    struct ifinfomsg peer_ifm = {};
    struct rtattr* peer_info =
        AddAttr(&req, VETH_INFO_PEER, &peer_ifm, sizeof(peer_ifm));
    AddAttr(&req, IFLA_IFNAME, peer, strlen(peer));
    EndNest(&req, peer_info);
    EndNest(&req, data);
  }
  EndNest(&req, linkinfo);
  return NetlinkRequestAckOrError(fd, seq, &req, req.hdr.nlmsg_len);
}

// Sets one attribute of an existing link.
PosixError SetLinkAttr(const FileDescriptor& fd, uint32_t seq, int index,
                       int type, const void* data, int len) {
  LinkRequest req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifm));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = seq;
  req.ifm.ifi_index = index;
  AddAttr(&req, type, data, len);
  return NetlinkRequestAckOrError(fd, seq, &req, req.hdr.nlmsg_len);
}

PosixErrorOr<int> MTU(const char* name) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor s, Socket(AF_INET, SOCK_DGRAM, 0));
  struct ifreq ifr = {};
  strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
  RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(s.get(), SIOCGIFMTU, &ifr));
  return ifr.ifr_mtu;
}

PosixErrorOr<MacAddress> HardwareAddress(const char* name) {
  ASSIGN_OR_RETURN_ERRNO(FileDescriptor s, Socket(AF_INET, SOCK_DGRAM, 0));
  struct ifreq ifr = {};
  strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
  RETURN_ERROR_IF_SYSCALL_FAIL(ioctl(s.get(), SIOCGIFHWADDR, &ifr));
  MacAddress mac;
  memcpy(mac.data(), ifr.ifr_hwaddr.sa_data, mac.size());
  return mac;
}

// The bridge br0 has ports pA and pB, the ends of veth pairs whose other ends
// oA and oB are outside the bridge. Frames are injected at oA, so they enter
// the bridge at pA. A UDP socket on br0's address shows whether a frame was
// passed up and accepted by br0's IP layer, and a packet socket on oB shows
// whether the bridge sent it out of pB.
class BridgeLocalDeliveryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
    SKIP_IF(IsRunningWithHostinet());

    netns_ =
        ASSERT_NO_ERRNO_AND_VALUE(Open("/proc/thread-self/ns/net", O_RDONLY));
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());

    FileDescriptor nl =
        ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
    PosixError err = NewLink(nl, kSeq, "bridge", "br0", nullptr);
    // Native Linux kernels may not be built with CONFIG_BRIDGE.
    SKIP_IF(!IsRunningOnGvisor() && err.errno_value() == EOPNOTSUPP);
    ASSERT_NO_ERRNO(err);
    ASSERT_NO_ERRNO(NewLink(nl, kSeq + 1, "veth", "pA", "oA"));
    ASSERT_NO_ERRNO(NewLink(nl, kSeq + 2, "veth", "pB", "oB"));

    const int br = if_nametoindex("br0");
    ASSERT_NE(br, 0);
    const int port_a = if_nametoindex("pA");
    ASSERT_NE(port_a, 0);
    const int port_b = if_nametoindex("pB");
    ASSERT_NE(port_b, 0);
    out_a_ = if_nametoindex("oA");
    ASSERT_NE(out_a_, 0);
    const int out_b = if_nametoindex("oB");
    ASSERT_NE(out_b, 0);

    // Linux gives a bridge without an explicit address the lowest port
    // address, which would make it indistinguishable from a port's.
    ASSERT_NO_ERRNO(SetLinkAttr(nl, kSeq + 3, br, IFLA_ADDRESS,
                                kBridgeMac.data(), kBridgeMac.size()));
    uint32_t seq = kSeq + 4;
    for (int port : {port_a, port_b}) {
      ASSERT_NO_ERRNO(
          SetLinkAttr(nl, seq++, port, IFLA_MASTER, &br, sizeof(br)));
    }
    for (int index : {br, port_a, port_b, out_a_, out_b}) {
      ASSERT_NO_ERRNO(LinkChangeFlags(index, IFF_UP, IFF_UP));
    }
    struct in_addr addr;
    ASSERT_EQ(inet_pton(AF_INET, kBridgeIP, &addr), 1);
    ASSERT_NO_ERRNO(LinkAddLocalAddr(nl, br, AF_INET, 24, &addr, sizeof(addr)));

    bridge_mac_ = ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("br0"));
    port_a_mac_ = ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("pA"));
    port_b_mac_ = ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("pB"));
    out_a_mac_ = ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("oA"));
    ASSERT_EQ(bridge_mac_, kBridgeMac);
    ASSERT_NE(port_a_mac_, port_b_mac_);
    for (const MacAddress& mac : {bridge_mac_, port_a_mac_, port_b_mac_}) {
      ASSERT_NE(mac, kUnknownMac);
      ASSERT_NE(mac, kNewPortAMac);
      ASSERT_NE(mac, kNewPortBMac);
    }

    sender_ = ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_RAW, 0));

    udp_ = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
    struct sockaddr_in bind_addr = {};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(kPort);
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ASSERT_THAT(bind(udp_.get(), reinterpret_cast<sockaddr*>(&bind_addr),
                     sizeof(bind_addr)),
                SyscallSucceeds());

    port_b_out_ = ASSERT_NO_ERRNO_AND_VALUE(
        Socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_IP)));
    struct sockaddr_ll ll = {};
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex = out_b;
    ASSERT_THAT(
        bind(port_b_out_.get(), reinterpret_cast<sockaddr*>(&ll), sizeof(ll)),
        SyscallSucceeds());

    // Linux enables bridge ports asynchronously once their carrier is up.
    const absl::Time deadline = absl::Now() + absl::Seconds(10);
    bool ready = false;
    while (!ready && absl::Now() < deadline) {
      const std::string marker = NextMarker();
      ASSERT_NO_FATAL_FAILURE(SendFrame(kBroadcastMac, marker));
      bool unused, up, out;
      ASSERT_NO_FATAL_FAILURE(ReceiveUntil(
          udp_.get(), 0, "", marker, absl::Milliseconds(100), &unused, &up));
      ASSERT_NO_FATAL_FAILURE(ReceiveUntil(port_b_out_.get(), kPayloadOffset,
                                           "", marker, absl::Milliseconds(100),
                                           &unused, &out));
      ready = up && out;
    }
    ASSERT_TRUE(ready) << "bridge did not start forwarding";
  }

  void TearDown() override {
    if (netns_.get() >= 0) {
      EXPECT_THAT(setns(netns_.get(), CLONE_NEWNET), SyscallSucceeds());
    }
  }

  std::string NextMarker() {
    return "bridge-local-delivery-" + std::to_string(next_marker_++);
  }

  // Sends a UDP datagram for kBridgeIP:kPort carrying payload in an Ethernet
  // frame for dst out of oA.
  void SendFrame(const MacAddress& dst, const std::string& payload) {
    std::string frame(kPayloadOffset + payload.size(), '\0');
    struct ethhdr eth = {};
    memcpy(eth.h_dest, dst.data(), ETH_ALEN);
    memcpy(eth.h_source, out_a_mac_.data(), ETH_ALEN);
    eth.h_proto = htons(ETH_P_IP);

    struct iphdr ip = {};
    ip.version = 4;
    ip.ihl = sizeof(ip) / 4;
    ip.tot_len = htons(frame.size() - sizeof(eth));
    ip.ttl = 64;
    ip.protocol = IPPROTO_UDP;
    ASSERT_EQ(inet_pton(AF_INET, kPeerIP, &ip.saddr), 1);
    ASSERT_EQ(inet_pton(AF_INET, kBridgeIP, &ip.daddr), 1);
    ip.check = IPChecksum(ip);

    struct udphdr udp = {};
    udp.source = htons(kPort);
    udp.dest = htons(kPort);
    udp.len = htons(sizeof(udp) + payload.size());

    memcpy(&frame[0], &eth, sizeof(eth));
    memcpy(&frame[sizeof(eth)], &ip, sizeof(ip));
    memcpy(&frame[sizeof(eth) + sizeof(ip)], &udp, sizeof(udp));
    memcpy(&frame[kPayloadOffset], payload.data(), payload.size());

    struct sockaddr_ll ll = {};
    ll.sll_family = AF_PACKET;
    ll.sll_protocol = htons(ETH_P_IP);
    ll.sll_ifindex = out_a_;
    ll.sll_halen = ETH_ALEN;
    memcpy(ll.sll_addr, dst.data(), ETH_ALEN);
    ASSERT_THAT(sendto(sender_.get(), frame.data(), frame.size(), 0,
                       reinterpret_cast<sockaddr*>(&ll), sizeof(ll)),
                SyscallSucceedsWithValue(frame.size()));
  }

  // Reads the next incoming packet on fd, whose payload starts at offset, and
  // returns its payload, or returns an empty string if none arrives within
  // timeout.
  void NextPayload(int fd, size_t offset, absl::Duration timeout,
                   std::string* payload) {
    payload->clear();
    const absl::Time deadline = absl::Now() + timeout;
    while (payload->empty()) {
      const absl::Duration left = deadline - absl::Now();
      if (left <= absl::ZeroDuration()) {
        return;
      }
      struct pollfd pfd = {.fd = fd, .events = POLLIN};
      const int n = poll(&pfd, 1, absl::ToInt64Milliseconds(left) + 1);
      ASSERT_THAT(n, SyscallSucceeds());
      if (n == 0) {
        return;
      }
      char buf[2048];
      struct sockaddr_ll from = {};
      socklen_t from_len = sizeof(from);
      const ssize_t len =
          recvfrom(fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from),
                   &from_len);
      if (len < 0 && errno == EAGAIN) {
        continue;
      }
      ASSERT_THAT(len, SyscallSucceeds());
      if (from.sll_family == AF_PACKET && from.sll_pkttype == PACKET_OUTGOING) {
        continue;
      }
      if (static_cast<size_t>(len) > offset) {
        payload->assign(buf + offset, len - offset);
      }
    }
  }

  // Reads from fd until a packet carrying until arrives or timeout passes, and
  // reports whether one carrying want arrived first.
  void ReceiveUntil(int fd, size_t offset, const std::string& want,
                    const std::string& until, absl::Duration timeout,
                    bool* seen_want, bool* seen_until) {
    *seen_want = false;
    *seen_until = false;
    const absl::Time deadline = absl::Now() + timeout;
    while (!*seen_until) {
      std::string payload;
      ASSERT_NO_FATAL_FAILURE(
          NextPayload(fd, offset, deadline - absl::Now(), &payload));
      if (payload.empty()) {
        return;
      }
      *seen_want |= payload == want;
      *seen_until = payload == until;
    }
  }

  // Sends a frame for dst from oA and reports whether it was delivered to the
  // UDP socket on br0 and whether it left the bridge through pB. A broadcast
  // sent after it, which reaches both, bounds how long to wait for it.
  void Deliver(const MacAddress& dst, bool* delivered, bool* forwarded) {
    const std::string marker = NextMarker();
    const std::string sentinel = NextMarker();
    ASSERT_NO_FATAL_FAILURE(SendFrame(dst, marker));
    ASSERT_NO_FATAL_FAILURE(SendFrame(kBroadcastMac, sentinel));
    ASSERT_NO_FATAL_FAILURE(Drain(udp_.get(), 0, marker, sentinel, delivered));
    ASSERT_NO_FATAL_FAILURE(
        Drain(port_b_out_.get(), kPayloadOffset, marker, sentinel, forwarded));
  }

  void Drain(int fd, size_t offset, const std::string& marker,
             const std::string& sentinel, bool* seen) {
    bool got_sentinel;
    ASSERT_NO_FATAL_FAILURE(ReceiveUntil(
        fd, offset, marker, sentinel, absl::Seconds(5), seen, &got_sentinel));
    ASSERT_TRUE(got_sentinel) << "broadcast " << sentinel << " not received";
    if (!*seen) {
      // Allow for the marker being reordered after the sentinel.
      bool unused;
      ASSERT_NO_FATAL_FAILURE(ReceiveUntil(fd, offset, sentinel, marker,
                                           absl::Milliseconds(200), &unused,
                                           seen));
    }
  }

  // Don't do cooperative save/restore because netstack state is not restored.
  // TODO(gvisor.dev/issue/4595): enable cooperative save tests.
  const DisableSave ds_;
  FileDescriptor netns_;
  FileDescriptor sender_;
  FileDescriptor udp_;
  FileDescriptor port_b_out_;
  int out_a_ = 0;
  MacAddress bridge_mac_;
  MacAddress port_a_mac_;
  MacAddress port_b_mac_;
  MacAddress out_a_mac_;
  int next_marker_ = 0;
};

// Linux: br_handle_frame_finish passes frames for a BR_FDB_LOCAL address up
// with br_pass_frame_up and does not forward them.
TEST_F(BridgeLocalDeliveryTest, BridgeAddressIsPassedUpNotForwarded) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(bridge_mac_, &delivered, &forwarded));
  EXPECT_TRUE(delivered);
  EXPECT_FALSE(forwarded);
}

TEST_F(BridgeLocalDeliveryTest, IngressPortAddressIsPassedUpNotForwarded) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(port_a_mac_, &delivered, &forwarded));
  EXPECT_TRUE(delivered);
  EXPECT_FALSE(forwarded);
}

TEST_F(BridgeLocalDeliveryTest, OtherPortAddressIsNotForwarded) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(port_b_mac_, &delivered, &forwarded));
  // The frame is passed up as PACKET_OTHERHOST, which ip_rcv drops.
  EXPECT_FALSE(delivered);
  EXPECT_FALSE(forwarded);
}

TEST_F(BridgeLocalDeliveryTest, UnknownUnicastIsFloodedNotPassedUp) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(kUnknownMac, &delivered, &forwarded));
  EXPECT_FALSE(delivered);
  EXPECT_TRUE(forwarded);
}

TEST_F(BridgeLocalDeliveryTest, BroadcastIsFloodedAndPassedUp) {
  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(kBroadcastMac, &delivered, &forwarded));
  EXPECT_TRUE(delivered);
  EXPECT_TRUE(forwarded);
}

// Linux: br_device_event calls br_fdb_changeaddr on NETDEV_CHANGEADDR, which
// replaces the port's BR_FDB_LOCAL entry.
TEST_F(BridgeLocalDeliveryTest, PortAddressChangeIsTracked) {
  FileDescriptor nl =
      ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  const int port_a = if_nametoindex("pA");
  ASSERT_NE(port_a, 0);
  const int port_b = if_nametoindex("pB");
  ASSERT_NE(port_b, 0);
  ASSERT_NO_ERRNO(SetLinkAttr(nl, kSeq + 10, port_a, IFLA_ADDRESS,
                              kNewPortAMac.data(), kNewPortAMac.size()));
  ASSERT_NO_ERRNO(SetLinkAttr(nl, kSeq + 11, port_b, IFLA_ADDRESS,
                              kNewPortBMac.data(), kNewPortBMac.size()));
  ASSERT_EQ(ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("pA")), kNewPortAMac);
  ASSERT_EQ(ASSERT_NO_ERRNO_AND_VALUE(HardwareAddress("pB")), kNewPortBMac);

  bool delivered, forwarded;
  ASSERT_NO_FATAL_FAILURE(Deliver(kNewPortAMac, &delivered, &forwarded));
  EXPECT_TRUE(delivered) << "new ingress-port address";
  EXPECT_FALSE(forwarded) << "new ingress-port address";
  ASSERT_NO_FATAL_FAILURE(Deliver(kNewPortBMac, &delivered, &forwarded));
  EXPECT_FALSE(delivered) << "new other-port address";
  EXPECT_FALSE(forwarded) << "new other-port address";
  ASSERT_NO_FATAL_FAILURE(Deliver(port_a_mac_, &delivered, &forwarded));
  EXPECT_FALSE(delivered) << "old ingress-port address";
  EXPECT_TRUE(forwarded) << "old ingress-port address";
  ASSERT_NO_FATAL_FAILURE(Deliver(port_b_mac_, &delivered, &forwarded));
  EXPECT_FALSE(delivered) << "old other-port address";
  EXPECT_TRUE(forwarded) << "old other-port address";
}

// LinkMTUTest runs each test in a new network namespace.
class LinkMTUTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_ADMIN)));
    SKIP_IF(IsRunningWithHostinet());
    ASSERT_THAT(unshare(CLONE_NEWNET), SyscallSucceeds());
    nl_ = ASSERT_NO_ERRNO_AND_VALUE(NetlinkBoundSocket(NETLINK_ROUTE));
  }

  // NewBridge creates a bridge. It skips the test if Linux does not support
  // bridges.
  void NewBridge(const char* name, uint32_t mtu = 0) {
    PosixError err = NewLink(nl_, seq_++, "bridge", name, nullptr, mtu);
    if (!IsRunningOnGvisor() && err.errno_value() == EOPNOTSUPP) {
      GTEST_SKIP() << "bridges are not supported";
    }
    ASSERT_NO_ERRNO(err);
  }

  PosixError SetMTU(int index, uint32_t mtu) {
    return SetLinkAttr(nl_, seq_++, index, IFLA_MTU, &mtu, sizeof(mtu));
  }

  PosixError SetMaster(int index, int master) {
    return SetLinkAttr(nl_, seq_++, index, IFLA_MASTER, &master,
                       sizeof(master));
  }

  FileDescriptor nl_;
  uint32_t seq_ = kSeq + 100;
};

// The ends of a veth pair have separate MTUs.
TEST_F(LinkMTUTest, VethEndsHaveSeparateMTUs) {
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "va", "vb"));
  const int va = if_nametoindex("va");
  ASSERT_NE(va, 0);
  ASSERT_NO_ERRNO(SetMTU(va, 1400));
  EXPECT_THAT(MTU("va"), IsPosixErrorOkAndHolds(1400));
  EXPECT_THAT(MTU("vb"), IsPosixErrorOkAndHolds(1500));
}

// A veth pair created without peer attributes gives its MTU to both ends.
TEST_F(LinkMTUTest, VethWithoutPeerAttributesGivesMTUToPeer) {
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "va", nullptr, 9000));
  EXPECT_THAT(MTU("va"), IsPosixErrorOkAndHolds(9000));
  // The new network namespace has only lo and the two ends.
  struct if_nameindex* names = if_nameindex();
  ASSERT_NE(names, nullptr);
  auto free_names = Cleanup([names] { if_freenameindex(names); });
  int peers = 0;
  for (struct if_nameindex* n = names; n->if_index != 0; n++) {
    const std::string name = n->if_name;
    if (name == "lo" || name == "va") {
      continue;
    }
    peers++;
    EXPECT_THAT(MTU(name.c_str()), IsPosixErrorOkAndHolds(9000)) << name;
  }
  EXPECT_EQ(peers, 1);
}

// Veth and bridge devices accept MTUs from 68 to 65535.
TEST_F(LinkMTUTest, MTULimits) {
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "va", "vb"));
  ASSERT_NO_FATAL_FAILURE(NewBridge("br0"));
  for (const char* name : {"va", "br0"}) {
    SCOPED_TRACE(name);
    const int index = if_nametoindex(name);
    ASSERT_NE(index, 0);
    for (uint32_t mtu : {67u, 65536u}) {
      EXPECT_THAT(SetMTU(index, mtu), PosixErrorIs(EINVAL, ::testing::_))
          << mtu;
    }
    for (uint32_t mtu : {68u, 65535u}) {
      EXPECT_NO_ERRNO(SetMTU(index, mtu)) << mtu;
      EXPECT_THAT(MTU(name), IsPosixErrorOkAndHolds(static_cast<int>(mtu)));
    }
  }
}

// The MTU of a bridge is the smallest MTU of its ports, or 1500 if it has no
// ports, until the MTU of the bridge is set. An MTU given when the bridge is
// created does not change this.
TEST_F(LinkMTUTest, BridgeMTUFollowsPorts) {
  ASSERT_NO_FATAL_FAILURE(NewBridge("br0", 1450));
  ASSERT_NO_FATAL_FAILURE(NewBridge("br1"));
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "pa", "oa"));
  const int br0 = if_nametoindex("br0");
  ASSERT_NE(br0, 0);
  const int br1 = if_nametoindex("br1");
  ASSERT_NE(br1, 0);
  const int pa = if_nametoindex("pa");
  ASSERT_NE(pa, 0);
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1450));

  ASSERT_NO_ERRNO(SetMTU(pa, 1400));
  ASSERT_NO_ERRNO(SetMaster(pa, br0));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1400));
  ASSERT_NO_ERRNO(SetMTU(pa, 1300));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1300));

  // A new master releases the port from its old master.
  ASSERT_NO_ERRNO(SetMaster(pa, br1));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1500));
  EXPECT_THAT(MTU("br1"), IsPosixErrorOkAndHolds(1300));

  // A master of 0 releases the port.
  ASSERT_NO_ERRNO(SetMaster(pa, 0));
  EXPECT_THAT(MTU("br1"), IsPosixErrorOkAndHolds(1500));
  EXPECT_NO_ERRNO(SetMaster(pa, 0));

  // An MTU set on the bridge stays.
  ASSERT_NO_ERRNO(SetMTU(br0, 1450));
  ASSERT_NO_ERRNO(SetMaster(pa, br0));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1450));
}

// An MTU given when a bridge is created must be from 68 to 65535.
TEST_F(LinkMTUTest, NewBridgeMTULimits) {
  for (uint32_t mtu : {67u, 65536u}) {
    PosixError err = NewLink(nl_, seq_++, "bridge", "br0", nullptr, mtu);
    if (!IsRunningOnGvisor() && err.errno_value() == EOPNOTSUPP) {
      GTEST_SKIP() << "bridges are not supported";
    }
    EXPECT_THAT(err, PosixErrorIs(EINVAL, ::testing::_)) << mtu;
    EXPECT_EQ(if_nametoindex("br0"), 0u) << mtu;
  }
}

// The MTU of a bridge also rises when the smallest MTU of its ports rises, and
// follows the ports that stay after a port device is deleted.
TEST_F(LinkMTUTest, BridgeMTUFollowsSmallestPort) {
  ASSERT_NO_FATAL_FAILURE(NewBridge("br0"));
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "pa", "oa"));
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "pb", "ob"));
  const int br0 = if_nametoindex("br0");
  const int pa = if_nametoindex("pa");
  const int pb = if_nametoindex("pb");
  ASSERT_NE(br0, 0);
  ASSERT_NE(pa, 0);
  ASSERT_NE(pb, 0);
  ASSERT_NO_ERRNO(SetMTU(pa, 1400));
  ASSERT_NO_ERRNO(SetMTU(pb, 1300));
  ASSERT_NO_ERRNO(SetMaster(pa, br0));
  ASSERT_NO_ERRNO(SetMaster(pb, br0));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1300));
  ASSERT_NO_ERRNO(SetMTU(pb, 9000));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1400));
  ASSERT_NO_ERRNO(SetMTU(pb, 1200));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1200));

  // Deleting a port device releases it from the bridge.
  LinkRequest req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifm));
  req.hdr.nlmsg_type = RTM_DELLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = seq_++;
  req.ifm.ifi_index = pb;
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(nl_, req.hdr.nlmsg_seq, &req,
                                           req.hdr.nlmsg_len));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1400));
}

// An MTU given when a veth device is created applies to that end only.
TEST_F(LinkMTUTest, NewVethMTU) {
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "va", "vb", 1400));
  EXPECT_THAT(MTU("va"), IsPosixErrorOkAndHolds(1400));
  EXPECT_THAT(MTU("vb"), IsPosixErrorOkAndHolds(1500));
}

// An MTU set on a bridge without ports stays when ports with other MTUs are
// added, even if it is larger than their MTUs.
TEST_F(LinkMTUTest, BridgeMTUSetBeforePorts) {
  ASSERT_NO_FATAL_FAILURE(NewBridge("br0"));
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "pa", "oa"));
  const int br0 = if_nametoindex("br0");
  const int pa = if_nametoindex("pa");
  ASSERT_NO_ERRNO(SetMTU(br0, 9000));
  ASSERT_NO_ERRNO(SetMaster(pa, br0));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(9000));
  ASSERT_NO_ERRNO(SetMaster(pa, 0));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(9000));
}

// A failed change of master releases the port from its old master first,
// as on Linux.
TEST_F(LinkMTUTest, FailedNewMasterReleasesPort) {
  ASSERT_NO_FATAL_FAILURE(NewBridge("br0"));
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "pa", "oa"));
  const int br0 = if_nametoindex("br0");
  const int pa = if_nametoindex("pa");
  const int oa = if_nametoindex("oa");
  ASSERT_NE(br0, 0);
  ASSERT_NE(pa, 0);
  ASSERT_NE(oa, 0);
  ASSERT_NO_ERRNO(SetMTU(pa, 1400));
  ASSERT_NO_ERRNO(SetMaster(pa, br0));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1400));
  // The same master again does nothing.
  EXPECT_NO_ERRNO(SetMaster(pa, br0));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1400));
  // A master that is not a bridge.
  EXPECT_THAT(SetMaster(pa, oa), PosixErrorIs(EOPNOTSUPP, ::testing::_));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1500));
  ASSERT_NO_ERRNO(SetMaster(pa, br0));
  // A master that does not exist.
  EXPECT_THAT(SetMaster(pa, 12345), PosixErrorIs(EINVAL, ::testing::_));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1500));
}

// An MTU set on a bridge to its current MTU does not stop the bridge MTU
// from following the ports, as on Linux.
TEST_F(LinkMTUTest, BridgeMTUSetToSameValue) {
  ASSERT_NO_FATAL_FAILURE(NewBridge("br0"));
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "pa", "oa"));
  const int br0 = if_nametoindex("br0");
  const int pa = if_nametoindex("pa");
  ASSERT_NE(br0, 0);
  ASSERT_NE(pa, 0);
  ASSERT_NO_ERRNO(SetMTU(br0, 1500));
  ASSERT_NO_ERRNO(SetMTU(pa, 1400));
  ASSERT_NO_ERRNO(SetMaster(pa, br0));
  EXPECT_THAT(MTU("br0"), IsPosixErrorOkAndHolds(1400));
}

// Returns true if a UDP datagram for kBridgeIP:kPort that is sent from peer
// to port reaches a UDP socket.
bool PortReceives(const char* port, const char* peer) {
  FileDescriptor udp = TEST_CHECK_NO_ERRNO_AND_VALUE(
      Socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
  struct sockaddr_in bind_addr = {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(kPort);
  TEST_PCHECK(bind(udp.get(), reinterpret_cast<sockaddr*>(&bind_addr),
                   sizeof(bind_addr)) == 0);
  FileDescriptor sender =
      TEST_CHECK_NO_ERRNO_AND_VALUE(Socket(AF_PACKET, SOCK_RAW, 0));
  const MacAddress dst = TEST_CHECK_NO_ERRNO_AND_VALUE(HardwareAddress(port));
  const MacAddress src = TEST_CHECK_NO_ERRNO_AND_VALUE(HardwareAddress(peer));
  const std::string payload = "port";
  std::string frame(kPayloadOffset + payload.size(), '\0');
  struct ethhdr eth = {};
  memcpy(eth.h_dest, dst.data(), ETH_ALEN);
  memcpy(eth.h_source, src.data(), ETH_ALEN);
  eth.h_proto = htons(ETH_P_IP);
  struct iphdr ip = {};
  ip.version = 4;
  ip.ihl = 5;
  ip.tot_len = htons(frame.size() - sizeof(eth));
  ip.ttl = 64;
  ip.protocol = IPPROTO_UDP;
  inet_pton(AF_INET, kPeerIP, &ip.saddr);
  inet_pton(AF_INET, kBridgeIP, &ip.daddr);
  ip.check = IPChecksum(ip);
  struct udphdr udph = {};
  udph.source = htons(kPort);
  udph.dest = htons(kPort);
  udph.len = htons(sizeof(udph) + payload.size());
  memcpy(&frame[0], &eth, sizeof(eth));
  memcpy(&frame[sizeof(eth)], &ip, sizeof(ip));
  memcpy(&frame[sizeof(eth) + sizeof(ip)], &udph, sizeof(udph));
  memcpy(&frame[kPayloadOffset], payload.data(), payload.size());
  struct sockaddr_ll ll = {};
  ll.sll_family = AF_PACKET;
  ll.sll_protocol = htons(ETH_P_IP);
  ll.sll_ifindex = if_nametoindex(peer);
  ll.sll_halen = ETH_ALEN;
  memcpy(ll.sll_addr, dst.data(), ETH_ALEN);
  for (int i = 0; i < 20; i++) {
    TEST_PCHECK(sendto(sender.get(), frame.data(), frame.size(), 0,
                       reinterpret_cast<sockaddr*>(&ll),
                       sizeof(ll)) == static_cast<ssize_t>(frame.size()));
    absl::SleepFor(absl::Milliseconds(100));
    char buf[64];
    if (recv(udp.get(), buf, sizeof(buf), 0) > 0) {
      return true;
    }
  }
  return false;
}

// Deleting a bridge releases its ports, and the ports keep working, as on
// Linux.
TEST_F(LinkMTUTest, DeleteBridgeWithPorts) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  ASSERT_NO_FATAL_FAILURE(NewBridge("br0"));
  ASSERT_NO_FATAL_FAILURE(NewBridge("br1"));
  ASSERT_NO_ERRNO(NewLink(nl_, seq_++, "veth", "pa", "oa"));
  const int br0 = if_nametoindex("br0");
  const int br1 = if_nametoindex("br1");
  const int pa = if_nametoindex("pa");
  const int oa = if_nametoindex("oa");
  ASSERT_NE(br0, 0);
  ASSERT_NE(br1, 0);
  ASSERT_NE(pa, 0);
  ASSERT_NE(oa, 0);
  for (int index : {pa, oa, br0}) {
    ASSERT_NO_ERRNO(LinkChangeFlags(index, IFF_UP, IFF_UP));
  }
  struct in_addr addr;
  ASSERT_EQ(inet_pton(AF_INET, kBridgeIP, &addr), 1);
  ASSERT_NO_ERRNO(LinkAddLocalAddr(nl_, pa, AF_INET, 24, &addr, sizeof(addr)));
  ASSERT_TRUE(PortReceives("pa", "oa"));
  ASSERT_NO_ERRNO(SetMaster(pa, br0));
  LinkRequest req = {};
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifm));
  req.hdr.nlmsg_type = RTM_DELLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.hdr.nlmsg_seq = seq_++;
  req.ifm.ifi_index = br0;
  ASSERT_NO_ERRNO(NetlinkRequestAckOrError(nl_, req.hdr.nlmsg_seq, &req,
                                           req.hdr.nlmsg_len));
  EXPECT_TRUE(PortReceives("pa", "oa"));
  EXPECT_NO_ERRNO(SetMTU(pa, 1300));
  EXPECT_NO_ERRNO(SetMaster(pa, 0));
  EXPECT_TRUE(PortReceives("pa", "oa"));
  EXPECT_NO_ERRNO(SetMaster(pa, br1));
  EXPECT_THAT(MTU("br1"), IsPosixErrorOkAndHolds(1300));
}

// A veth pair cannot be created with an MTU that is not valid, and creation
// that fails leaves no device.
TEST_F(LinkMTUTest, NewVethMTULimits) {
  for (uint32_t mtu : {67u, 65536u}) {
    EXPECT_THAT(NewLink(nl_, seq_++, "veth", "va", "vb", mtu),
                PosixErrorIs(EINVAL, ::testing::_))
        << mtu;
    EXPECT_EQ(if_nametoindex("va"), 0u) << mtu;
    EXPECT_EQ(if_nametoindex("vb"), 0u) << mtu;
    EXPECT_THAT(NewLink(nl_, seq_++, "veth", "va", nullptr, mtu),
                PosixErrorIs(EINVAL, ::testing::_))
        << mtu;
    EXPECT_EQ(if_nametoindex("va"), 0u) << mtu;
  }
}

}  // namespace

}  // namespace testing
}  // namespace gvisor
