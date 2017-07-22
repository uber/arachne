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

package defines

import (
	"syscall"
	"time"
)

// Global constants
const (
	ArachneService                  = "arachne"
	ArachneVersion                  = "0.6.0" //TODO Read from file version.git
	ArachneTestConfigFilePathLinux  = "../arachned/config/test_target_config_linux.json"
	ArachneTestConfigFilePathDarwin = "../arachned/config/test_target_config_darwin.json"
	BatchIntervalEchoingPerc        = 0.75
	BatchIntervalUploadStats        = 0.95
	ChannelInBufferSize             = 800
	ChannelOutBufferSize            = 800
	DNSRefreshInterval              = 12 * time.Hour
	HTTPResponseHeaderTimeout       = 10 * time.Second
	IPTTL                           = 64
	IPv4HeaderLength                = 20
	IPv6HeaderLength                = 40
	LogFileSizeMaxMB                = 15
	LogFileSizeKeepKB               = 250
	OrchestratorRESTConf            = "conf"
	MaxNumRemoteTargets             = 250
	MaxNumSrcTCPPorts               = 512
	MaxPacketSizeBytes              = 1500
	MinBatchInterval                = 10 * time.Second
	NumQOSDCSPValues                = 11
	PcapMaxSnapLen                  = 128
	PortHTTP                        = 80
	PortHTTPS                       = 443
	TCPHeaderLength                 = 20
	TCPWindowSize                   = 0xaaaa
	TimestampPayloadLengthBytes     = 15
)

// Internet Address Families
const (
	AfInet  = syscall.AF_INET
	AfInet6 = syscall.AF_INET6
)
