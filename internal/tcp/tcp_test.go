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

package tcp

import (
	"encoding/hex"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/ip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPkt struct {
	hexData string
	name    string
}

func TestParsePktTCP(t *testing.T) {
	assert := assert.New(t)

	pkt := testPkt{
		hexData: "4500003791cc4000380651910a01010a0a00000a7918ac4f768dae70fbf6c7115012aaaa9aed0000010000000ed0de286824a952740000",
		name:    "TCP test packet (ipv4), TCP Src Port: 31000, TCP Dst Port 44111, payload TimeStamp: 2017-06-22T21:06:48.615076468+00:00",
	}
	data, _ := hex.DecodeString(pkt.hexData)

	createdPkt := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	require.NotNil(t, createdPkt, "creating packet %s failed", pkt.name)

	tcpHeader, payload, err := parsePktTCP(createdPkt)
	require.NoError(t, err, "decoding TCP header from packet %s failed: %v", pkt.name, err)

	assert.Equal(tcpHeader.SrcPort, layers.TCPPort(31000), "unexpectedly formatted TCP Src Port")
	assert.Equal(tcpHeader.DstPort, layers.TCPPort(44111), "unexpectedly formatted TCP Dst Port")

	expectedTime, err := time.Parse(time.RFC3339, "2017-06-22T21:06:48.615076468+00:00")
	require.NoError(t, err, "parsing timestamp from TCP packet %s failed: %v", pkt.name, err)

	assert.Equal(payload, expectedTime, "unexpectedly formatted TCP payload timestamp")
}

func TestParsePktIP(t *testing.T) {
	assert := assert.New(t)

	pkt := testPkt{
		hexData: "4558003791cc4000380651910a01010a0a00000a7918ac4f768dae70fbf6c7115012aaaa9aed0000010000000ed0de286824a952740000",
		name:    "IPv4 test packet, Src IP 10.1.1.10, DSCP value 88",
	}

	data, _ := hex.DecodeString(pkt.hexData)
	createdPkt := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	require.NotNil(t, createdPkt, "creating packet %s failed", pkt.name)

	srcIP, dscpv, err := parsePktIP(createdPkt)
	require.NoError(t, err, "decoded IP Header from packet %s failed: %v", pkt.name, err)

	expectedIP := net.ParseIP("10.1.1.10")
	assert.Equal(expectedIP.Equal(srcIP), true, "unexpectedly formatted Src IP address")
	assert.Equal(dscpv, ip.DSCPValue(88), "unexpectedly formatted IP Header DSCP value")
}

func TestMakePkt(t *testing.T) {
	assert := assert.New(t)

	var (
		af          int
		srcAddr     net.IP
		dstAddr     net.IP
		srcPort     layers.TCPPort
		dstPort     layers.TCPPort
		expectedPkt testPkt
		want        []byte
		err         error
	)

	// IPv4
	af = defines.AfInet
	srcAddr = net.IPv4(10, 0, 0, 1)
	dstAddr = net.IPv4(20, 0, 0, 1)
	srcPort = layers.TCPPort(31100)
	dstPort = layers.TCPPort(44111)
	// Darwin uses Host-byte order for Length and FragOffset in IPv4 Headers
	switch runtime.GOOS {
	case "linux":
		expectedPkt = testPkt{
			hexData: "456400280000000040065c6b0a00000114000001797cac4f00000000000000005002aaaac16a0000",
			name:    "Linux IPv4/TCP test Packet, SrcIP: 10.0.0.1, DstIP: 20.0.0.1, SrcPort 31100, DstPort: 44111, Flags: SYN",
		}
	case "darwin":
		expectedPkt = testPkt{
			hexData: "4564280000000000400634930a00000114000001797cac4f00000000000000005002aaaac16a0000",
			name:    "Darwin IPv4/TCP test Packet, SrcIP: 10.0.0.1, DstIP: 20.0.0.1, SrcPort 31100, DstPort: 44111, Flags: SYN",
		}
	default:
		t.Fatalf("unsupported OS for testing: " + runtime.GOOS)
	}

	want, _ = hex.DecodeString(expectedPkt.hexData)
	got, err := makePkt(af, srcAddr, dstAddr, srcPort, dstPort, 100, tcpFlags{syn: true}, 0, 0)
	require.NoError(t, err, "creating IPv4 TCP packet %s failed: %v", expectedPkt.name, err)

	assert.Equal(got, want, "unexpectedly formatted IPv4 TCP Syn packet generated")

	// IPv6
	af = defines.AfInet6
	srcAddr = net.IP{0x20, 0x01, 0x06, 0x13, 0x93, 0xFF, 0x8B, 0x40, 0, 0, 0, 0, 0, 0, 0, 1}
	dstAddr = net.IP{0x20, 0x04, 0x0B, 0xBD, 0x03, 0x2F, 0x0E, 0x41, 0, 0, 0, 0, 0, 0, 0, 2}
	srcPort = layers.TCPPort(1200)
	dstPort = layers.TCPPort(44)
	expectedPkt = testPkt{
		hexData: "66400000001406002001061393ff8b40000000000000000120040bbd032f0e41000000000000000204b0002c00000000000000005002aaaa7dd40000",
		name:    "IPv6/TCP test Packet, SrcIP: 2001:613:93ff:8b40::1, DstIP: 2004:bbd:32f:e41::2, SrcPort 1200, DstPort: 44, Flags: SYN",
	}

	want, _ = hex.DecodeString(expectedPkt.hexData)
	got, err = makePkt(af, srcAddr, dstAddr, srcPort, dstPort, 100, tcpFlags{syn: true}, 0, 0)
	require.NoError(t, err, "creating IPv6 TCP packet %s failed: %v", expectedPkt.name, err)

	assert.Equal(want, got, "unexpectedly formatted IPv6 TCP Syn packet generated")
}
