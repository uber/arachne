// Copyright (c) 2016 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package ip

import (
	"fmt"
	"net"
	"syscall"

	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

// Conn represents the underyling functionality to send and recv Arachne echo requests
type Conn struct {
	SrcAddr net.IP
	AF      int
	sendFD  int
	recvSrc gopacket.PacketDataSource
}

// Close is used to close a Conn's send file descriptor and Recv packet source
func (c *Conn) Close() error {
	return syscall.Close(c.sendFD)
}

// NextPacket gets the next available packet from the PacketDataSource
func (c *Conn) NextPacket() (gopacket.Packet, error) {
	data, _, err := c.recvSrc.ReadPacketData()
	if err != nil {
		return nil, err
	}
	return gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.DecodeOptions{Lazy: true}), nil
}

// Sendto operates on a Conn file descriptor and mirrors the Sendto syscall
func (c *Conn) Sendto(b []byte, to net.IP) error {
	sockAddr, err := ipToSockaddr(c.AF, to, 0)
	if err != nil {
		return err
	}

	return syscall.Sendto(c.sendFD, b, 0, sockAddr)
}

// getSendSocket will create a raw socket for sending data
func getSendSocket(af int) (int, error) {
	fd, err := syscall.Socket(af, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return 0, err
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return 0, err
	}

	return fd, nil
}

func getRecvSource(listenPort uint32, intf string) (gopacket.PacketDataSource, error) {
	// Filter for tcp packets coming into ListenPort, http, or HTTPS and contain a SYN flag
	filter := fmt.Sprintf("(dst port %d or dst port %d or dst port %d) and (tcp[13] & 2 != 0)",
		listenPort,
		defines.PortHTTP,
		defines.PortHTTPS)

	handle, err := pcap.OpenLive(intf, defines.PcapMaxSnapLen, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	if err = handle.SetBPFFilter(filter); err != nil {
		return nil, err
	}

	handle.SetDirection(pcap.DirectionIn)

	return handle, nil
}

// NewConn returns a raw socket connection to send and receive packets
func NewConn(af int, listenPort uint32, intf string, srcAddr net.IP, logger *log.Logger) *Conn {
	fds, err := getSendSocket(af)
	if err != nil {
		logger.Fatal("Error creating send socket",
			zap.Int("Address Family", af),
			zap.Error(err))
	}

	rs, err := getRecvSource(listenPort, intf)
	if err != nil {
		logger.Fatal("Error creating recv source",
			zap.Uint32("listenPort", listenPort),
			zap.String("interface", intf),
			zap.Error(err))
	}

	return &Conn{
		SrcAddr: srcAddr,
		AF:      af,
		sendFD:  fds,
		recvSrc: rs,
	}
}

func getIPHeaderLayerV6(tos uint8, tcpLen int, srcIP, dstIP net.IP) *layers.IPv6 {
	return &layers.IPv6{
		Version:      6,
		TrafficClass: tos,
		Length:       uint16(tcpLen),
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        srcIP,
		DstIP:        dstIP,
	}
}

// GetIPHeaderLayer returns the appriately versioned gopacket IP layer
func GetIPHeaderLayer(af int, tos uint8, tcpLen int, srcIP, dstIP net.IP) (gopacket.NetworkLayer, error) {
	switch af {
	case defines.AfInet:
		return getIPHeaderLayerV4(tos, tcpLen, srcIP, dstIP), nil
	case defines.AfInet6:
		return getIPHeaderLayerV6(tos, tcpLen, srcIP, dstIP), nil
	}

	return nil, fmt.Errorf("invalid address family")
}

func ipToSockaddr(family int, ip net.IP, port int) (syscall.Sockaddr, error) {
	switch family {
	case syscall.AF_INET:
		if len(ip) == 0 {
			ip = net.IPv4zero
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, &net.AddrError{Err: "non-IPv4 address", Addr: ip.String()}
		}
		sa := &syscall.SockaddrInet4{Port: port}
		copy(sa.Addr[:], ip4)
		return sa, nil
	case syscall.AF_INET6:
		if len(ip) == 0 || ip.Equal(net.IPv4zero) {
			ip = net.IPv6zero
		}
		ip6 := ip.To16()
		if ip6 == nil {
			return nil, &net.AddrError{Err: "non-IPv6 address", Addr: ip.String()}
		}
		sa := &syscall.SockaddrInet6{Port: port}
		copy(sa.Addr[:], ip6)
		return sa, nil
	}
	return nil, &net.AddrError{Err: "invalid address family", Addr: ip.String()}
}
