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

package collector

import (
	coreLog "log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/uber/arachne/config"
	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/ip"
	"github.com/uber/arachne/internal/log"
	"github.com/uber/arachne/internal/network"
	"github.com/uber/arachne/internal/tcp"
	"github.com/uber/arachne/internal/util"
	"github.com/uber/arachne/metrics"

	"github.com/google/gopacket/layers"
	"github.com/spacemonkeygo/monotime"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func statsUploadMock(
	glr *config.RemoteConfig,
	sr metrics.Reporter,
	target string,
	remotes config.RemoteStore,
	QOSDSCP ip.DSCPValue,
	srcPort layers.TCPPort,
	r *report,
	logger *log.Logger,
) {
	return
}

func TestRun(t *testing.T) {

	l, err := zap.NewDevelopment()
	if err != nil {
		coreLog.Fatal(err)
	}
	logger := &log.Logger{
		Logger:    l,
		PIDPath:   "",
		RemovePID: util.RemovePID,
	}

	source := net.IPv4(10, 0, 0, 1)
	target := net.IPv4(20, 0, 0, 1)
	unreachableTarget := net.IPv4(21, 0, 0, 1)
	sourceIPv6 := net.IP{0x20, 0x01, 0x06, 0x13, 0x93, 0xFF, 0x8B, 0x40, 0, 0, 0, 0, 0, 0, 0, 1}
	targetIPv6 := net.IP{0x20, 0x04, 0x0B, 0xBD, 0x03, 0x2F, 0x0E, 0x41, 0, 0, 0, 0, 0, 0, 0, 2}
	currentDSCP := ip.DSCPBulkHigh
	sp := layers.TCPPort(32000)
	CLIArgs := config.CLIConfig{
		SenderOnlyMode: func() *bool { b := false; return &b }(),
		Foreground:     func() *bool { b := false; return &b }(),
	}
	gl := config.Global{
		RemoteConfig: new(config.RemoteConfig),
		CLI:          &CLIArgs,
	}

	remotes := make(map[string]config.Remote, defines.MaxNumRemoteTargets)
	remotes[target.String()] = config.Remote{
		IP:       target,
		AF:       network.Family(&target),
		Hostname: "target.domain.com",
		External: false}
	remotes[unreachableTarget.String()] = config.Remote{
		IP:       unreachableTarget,
		AF:       network.Family(&unreachableTarget),
		Hostname: "unreachabletarget.domain.com",
		External: false}
	remotes[targetIPv6.String()] = config.Remote{
		IP:       targetIPv6,
		AF:       network.Family(&targetIPv6),
		Hostname: "targetIPv6.domain.com",
		External: true}
	ms := make(messageStore)
	rs := make(resultStore)

	sentC := make(chan tcp.Message, defines.ChannelOutBufferSize)
	rcvdC := make(chan tcp.Message, defines.ChannelInBufferSize)
	var finishedCycleUpload sync.WaitGroup
	completeCycleUpload := make(chan bool, 1)
	kill := make(chan struct{})

	go func() {
		batchWorker(&gl, sentC, rcvdC, remotes, ms, rs, &currentDSCP, statsUploadMock, nil,
			completeCycleUpload, kill, &finishedCycleUpload, logger)
	}()
	time.Sleep(50 * time.Millisecond)

	const initialSequence = uint32(50)
	sentC <- tcp.Message{
		Type:    tcp.EchoRequest,
		SrcAddr: source,
		DstAddr: target,
		Af:      defines.AfInet,
		SrcPort: sp,
		QosDSCP: currentDSCP,
		Ts: tcp.Timestamp{
			Run:  monotime.Now(),
			Unix: time.Now()},
		Seq: initialSequence,
		Ack: uint32(0),
	}
	time.Sleep(50 * time.Millisecond)
	rcvdC <- tcp.Message{
		Type:    tcp.EchoReply,
		SrcAddr: target,
		DstAddr: source,
		Af:      defines.AfInet,
		SrcPort: sp,
		QosDSCP: currentDSCP,
		Ts: tcp.Timestamp{
			Run:     monotime.Now(),
			Payload: time.Now()},
		Seq: uint32(346),
		Ack: initialSequence + 1,
	}
	time.Sleep(50 * time.Millisecond)

	sentC <- tcp.Message{
		Type:    tcp.EchoRequest,
		SrcAddr: source,
		DstAddr: unreachableTarget,
		Af:      defines.AfInet,
		SrcPort: sp,
		QosDSCP: currentDSCP,
		Ts: tcp.Timestamp{
			Run:  monotime.Now(),
			Unix: time.Now()},
		Seq: uint32(60),
	}
	time.Sleep(50 * time.Millisecond)

	sentC <- tcp.Message{
		Type:    tcp.EchoRequest,
		SrcAddr: sourceIPv6,
		DstAddr: targetIPv6,
		Af:      defines.AfInet6,
		SrcPort: sp,
		QosDSCP: currentDSCP,
		Ts: tcp.Timestamp{
			Run:  monotime.Now(),
			Unix: time.Now()},
		Seq: uint32(70),
	}
	time.Sleep(50 * time.Millisecond)

	finishedCycleUpload.Add(1)
	// Request from Collector to complete all stats uploads for this batch cycle
	completeCycleUpload <- true
	// Wait till the above request is fulfilled
	finishedCycleUpload.Wait()

	assert := assert.New(t)
	_, existsProbe := ms.existsSent(target.String(), (ip.GetDSCP).Pos(currentDSCP, logger), sp)
	assert.True(existsProbe, "Probe to "+target.String()+" should exist in 'sent' of messageStore")
	_, existsReply := ms.existsRcvd(target.String(), (ip.GetDSCP).Pos(currentDSCP, logger), sp)
	assert.True(existsReply, "Reply from "+target.String()+" should exist in 'rcvd' of messageStore")
	assert.Contains(ms, targetIPv6.String(), "Probe to "+targetIPv6.String()+
		" should exist in 'sent' of messageStore")

	assert.Contains(remotes, unreachableTarget.String(), "Probe to "+unreachableTarget.String()+
		" should exist in remotes[]")
	assert.Contains(rs, target.String(), "Probe to "+target.String()+" should exist in resultStore")

	assert.Contains(rs, unreachableTarget.String(), "Zero-ed probe to "+unreachableTarget.String()+
		" should exist in resultStore")
	close(completeCycleUpload)
}
