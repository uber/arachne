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

	"github.com/stretchr/testify/assert"
	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/log"
	"github.com/uber/arachne/internal/util"
	"go.uber.org/zap"
)

func TestReceiver(t *testing.T) {
	var interfaceName string
	var err error

	l, _ := zap.NewDevelopment()
	logger := &log.Logger{
		Logger:    l,
		PIDPath:   "",
		RemovePID: util.RemovePID,
	}

	switch runtime.GOOS {
	case "linux":
		interfaceName = "eth0"
	case "darwin":
		interfaceName = "en0"
	default:
		t.Fatalf("unsupported OS for testing: " + runtime.GOOS)
	}

	srcIP := net.IPv4(10, 0, 0, 1)
	sentC := make(chan Message, defines.ChannelOutBufferSize)
	rcvdC := make(chan Message, defines.ChannelInBufferSize)
	receiverDone := make(chan struct{})
	err = Receiver("ipInvalid", &srcIP, 44111, interfaceName, sentC, rcvdC, receiverDone, logger)
	assert.Error(t, err, "Non IPv4 or IPv6 family should not be handled")
	close(receiverDone)

	err = Receiver("ip4", &srcIP, 44111, interfaceName, sentC, rcvdC, receiverDone, logger)
	if err == nil {
		t.Fatal("Non IPv4 or IPv6 family should not be handled")
	}

}

func TestMakePkt(t *testing.T) {
	assert := assert.New(t)

	var (
		af             string
		srcAddr        net.IP
		dstAddr        net.IP
		srcPort        uint16
		dstPort        uint16
		expectedPacket = []byte{}
		packet         = []byte{}
		err            error
	)

	af = "ip4"
	srcAddr = net.IPv4(10, 0, 0, 1)
	dstAddr = net.IPv4(20, 0, 0, 1)
	srcPort = uint16(31100)
	dstPort = uint16(44111)
	expectedPacket = []byte{121, 124, 172, 79, 0, 0, 0, 100, 0, 0, 0, 0, 80, 2, 170, 170, 193, 6, 0, 0}
	packet, err = makePkt(af, &srcAddr, &dstAddr, srcPort, dstPort, syn, 100, 0)
	if err != nil {
		t.Fatalf("error creating an IPv4 TCP SYN packet (%v)", err)
	}
	assert.Equal(expectedPacket, packet, "unexpectedly formatted IPv4 TCP SYN packet generated")

	af = "ip6"
	srcAddr = net.IP{0x20, 0x01, 0x06, 0x13, 0x93, 0xFF, 0x8B, 0x40, 0, 0, 0, 0, 0, 0, 0, 1}
	dstAddr = net.IP{0x20, 0x04, 0x0B, 0xBD, 0x03, 0x2F, 0x0E, 0x41, 0, 0, 0, 0, 0, 0, 0, 2}
	srcPort = uint16(1200)
	dstPort = uint16(44)
	expectedPacket = []byte{4, 176, 0, 44, 0, 0, 0, 100, 0, 0, 0, 0, 80, 2, 170, 170, 125, 112, 0, 0}
	packet, err = makePkt(af, &srcAddr, &dstAddr, srcPort, dstPort, syn, 100, 0)
	if err != nil {
		t.Fatalf("error creating an IPv6 TCP SYN packet (%v)", err)
	}
	assert.Equal(expectedPacket, packet, "unexpectedly formatted IPv6 TCP SYN packet generated")
}
