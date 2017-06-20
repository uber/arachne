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
	"net"

	"github.com/uber/arachne/defines"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// GetIPLayerOptions returns the gopacket options for serialization specific to Linux.
// In linux, gopacket correctly computes the ip Header lengths and checksum.
func GetIPLayerOptions() gopacket.SerializeOptions {
	return gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
}

func getIPHeaderLayerV4(tos uint8, tcpLen uint16, srcIP net.IP, dstIP net.IP) *layers.IPv4 {
	return &layers.IPv4{
		Version:  4, // IP Version 4
		TOS:      tos,
		Protocol: layers.IPProtocolTCP,
		TTL:      defines.IPTTL,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
}
