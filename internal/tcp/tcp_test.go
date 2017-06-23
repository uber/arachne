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
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/uber/arachne/defines"

	"github.com/stretchr/testify/assert"
)

func TestParsePktTCP(t *testing.T) {
	assert := assert.New(t)

	pktData := []byte{69, 0, 0, 55, 145, 204, 64, 0, 56, 6, 81, 145, 10, 1, 1, 10, 10, 0, 0, 10, 121, 24, 172, 79, 118, 141, 174, 112, 251, 246, 199, 17, 80, 18, 170, 170, 154, 237, 0, 0, 1, 0, 0, 0, 14, 208, 222, 40, 104, 36, 169, 82, 116, 0, 0}
	pkt := gopacket.NewPacket(pktData, layers.LayerTypeIPv4, gopacket.Default)

	tcpHeader, payload, err := parsePktTCP(pkt)
	if err != nil {
		t.Fatal("Extracting TCP Header and Payload from gopacket failed", err)
	}

	assert.Equal(tcpHeader.SrcPort, layers.TCPPort(31000), "unexpectedly formatted TCP Src Port")
	assert.Equal(tcpHeader.DstPort, layers.TCPPort(44111), "unexpectedly formatted TCP Dst Port")

	expectedTime, err := time.Parse(time.RFC3339, "2017-06-22T21:06:48.615076468+00:00")
	if err != nil {
		t.Fatal("Error parsing timestamp", err)
	}
	assert.Equal(payload, expectedTime, "unexpectedly formatted TCP paylaod timestamp")

}

func TestParsePktIP(t *testing.T) {
	assert := assert.New(t)

	pktData := []byte{69, 88, 0, 55, 145, 204, 64, 0, 56, 6, 81, 145, 10, 1, 1, 10, 10, 0, 0, 10, 121, 24, 172, 79, 118, 141, 174, 112, 251, 246, 199, 17, 80, 18, 170, 170, 154, 237, 0, 0, 1, 0, 0, 0, 14, 208, 222, 40, 104, 36, 169, 82, 116, 0, 0}
	pkt := gopacket.NewPacket(pktData, layers.LayerTypeIPv4, gopacket.Default)

	srcIP, dscpv, err := parsePktIP(pkt)
	if err != nil {
		t.Fatal("Extracting IP Src Port and DSCP Value from gopacket failed", err)
	}
	expectedIP := net.ParseIP("10.1.1.10")

	assert.Equal(expectedIP.Equal(srcIP), true, "unexpectedly formatted Src IP address")
	assert.Equal(dscpv, DSCPValue(88), "unexpectedly formatted IP Header DSCP value")
}

func TestMakePkt(t *testing.T) {
	assert := assert.New(t)

	var (
		af             int
		srcAddr        net.IP
		dstAddr        net.IP
		srcPort        uint16
		dstPort        uint16
		expectedPacket = []byte{}
		packet         = []byte{}
		err            error
	)

	// IPv4
	af = defines.AfInet
	srcAddr = net.IPv4(10, 0, 0, 1)
	dstAddr = net.IPv4(20, 0, 0, 1)
	srcPort = uint16(31100)
	dstPort = uint16(44111)
	// Darwin uses Host-byte order for Length and FragOffset in IPv4 Headers
	switch runtime.GOOS {
	case "linux":
		expectedPacket = []byte{69, 100, 0, 40, 0, 0, 0, 0, 64, 6, 92, 107, 10, 0, 0, 1, 20, 0, 0, 1, 121, 124, 172, 79, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 170, 170, 193, 106, 0, 0}
	case "darwin":
		expectedPacket = []byte{69, 100, 40, 0, 0, 0, 0, 0, 64, 6, 52, 147, 10, 0, 0, 1, 20, 0, 0, 1, 121, 124, 172, 79, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 170, 170, 193, 106, 0, 0}
	default:
		t.Fatalf("unsupported OS for testing: " + runtime.GOOS)
	}

	packet, err = makePkt(af, srcAddr, dstAddr, srcPort, dstPort, 100, tcpFlags{syn: true}, 0, 0)
	if err != nil {
		t.Fatal("error creating IPv4 TCP SYN packet", err)
	}

	assert.Equal(packet, expectedPacket, "unexpectedly formatted IPv4 TCP Syn packet generated")

	// IPv6
	af = defines.AfInet6
	srcAddr = net.IP{0x20, 0x01, 0x06, 0x13, 0x93, 0xFF, 0x8B, 0x40, 0, 0, 0, 0, 0, 0, 0, 1}
	dstAddr = net.IP{0x20, 0x04, 0x0B, 0xBD, 0x03, 0x2F, 0x0E, 0x41, 0, 0, 0, 0, 0, 0, 0, 2}
	srcPort = uint16(1200)
	dstPort = uint16(44)
	expectedPacket = []byte{102, 64, 0, 0, 0, 20, 6, 0, 32, 1, 6, 19, 147, 255, 139, 64, 0, 0, 0, 0, 0, 0, 0, 1, 32, 4, 11, 189, 3, 47, 14, 65, 0, 0, 0, 0, 0, 0, 0, 2, 4, 176, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 80, 2, 170, 170, 125, 212, 0, 0}
	packet, err = makePkt(af, srcAddr, dstAddr, srcPort, dstPort, 100, tcpFlags{syn: true}, 0, 0)
	if err != nil {
		t.Fatal("error creating IPv6 TCP SYN packet", err)
	}

	assert.Equal(packet, expectedPacket, "unexpectedly formatted IPv6 TCP Syn packet generated")
}
