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
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/uber/arachne/config"
	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/ip"
	"github.com/uber/arachne/internal/log"
	"github.com/uber/arachne/internal/tcp"
	"github.com/uber/arachne/metrics"

	"github.com/fatih/color"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const hostWidth = 51
const tableWidth = 119

// report of metrics measured
type report struct {
	latency2Way time.Duration
	latency1Way time.Duration
	timedOut    bool
}

// map[target address string] => *[QOS_DCSP_VALUE] =>map[source port]
type resultStore map[string]*[defines.NumQOSDCSPValues]map[layers.TCPPort]report
type messageStore map[string]*[defines.NumQOSDCSPValues]srcPortScopedMessageStore

type srcPortScopedMessageStore struct {
	sent srcPortScopedMessages
	rcvd srcPortScopedMessages
}
type srcPortScopedMessages map[layers.TCPPort]tcp.Message

func (ms messageStore) target(target string, QosDSCPIndex uint8) *srcPortScopedMessageStore {
	// TODO: validate dscp is in range or create a dscp type alias
	if _, exists := ms[target]; !exists {
		ms[target] = new([defines.NumQOSDCSPValues]srcPortScopedMessageStore)
	}
	if ms[target][QosDSCPIndex].sent == nil {
		ms[target][QosDSCPIndex].sent = make(srcPortScopedMessages)
	}
	if ms[target][QosDSCPIndex].rcvd == nil {
		ms[target][QosDSCPIndex].rcvd = make(srcPortScopedMessages)
	}
	return &ms[target][QosDSCPIndex]
}

func (spsm srcPortScopedMessages) add(srcPort layers.TCPPort, message tcp.Message) {
	spsm[srcPort] = message
}

func (ms messageStore) sentAdd(target string, QosDSCPIndex uint8, srcPort layers.TCPPort, message tcp.Message) {
	ms.target(target, QosDSCPIndex).sent.add(srcPort, message)
}

func (ms messageStore) rcvdAdd(target string, QosDSCPIndex uint8, srcPort layers.TCPPort, message tcp.Message) {
	ms.target(target, QosDSCPIndex).rcvd.add(srcPort, message)
}

func (ms messageStore) existsRcvd(target string, QosDSCPIndex uint8, srcPort layers.TCPPort) (tcp.Message, bool) {

	if _, exists := ms[target]; !exists {
		return tcp.Message{}, false
	}
	if ms[target][QosDSCPIndex].rcvd == nil {
		return tcp.Message{}, false
	}
	matchedMsg, existsMatch := ms[target][QosDSCPIndex].rcvd[srcPort]
	if !existsMatch {
		return tcp.Message{}, false
	}
	return matchedMsg, true
}

func (ms messageStore) existsSent(target string, QosDSCPIndex uint8, srcPort layers.TCPPort) (tcp.Message, bool) {

	if _, exists := ms[target]; !exists {
		return tcp.Message{}, false
	}
	if ms[target][QosDSCPIndex].sent == nil {
		return tcp.Message{}, false
	}
	matchedMsg, existsMatch := ms[target][QosDSCPIndex].sent[srcPort]
	if !existsMatch {
		return tcp.Message{}, false
	}
	return matchedMsg, true
}

func (rs resultStore) add(target string, QosDSCPIndex uint8, srcPort layers.TCPPort, r report) {

	if rs[target] == nil {
		var resDSCP [defines.NumQOSDCSPValues]map[layers.TCPPort]report
		rs[target] = &resDSCP
	}
	if rs[target][QosDSCPIndex] == nil {
		rs[target][QosDSCPIndex] = make(map[layers.TCPPort]report)
	}
	rs[target][QosDSCPIndex][srcPort] = r
}

type resultWalker func(report, string, string, layers.TCPPort, bool, *log.Logger)

func (rs resultStore) walkResults(
	remotes config.RemoteStore,
	currentDSCP *ip.DSCPValue,
	foreground bool,
	logger *log.Logger,
	walkerF ...resultWalker) {

	for target, r := range rs {
		remote, existsTarget := remotes[target]
		if !existsTarget {
			logger.Error("host exists in resultStore, but not in remoteStore",
				zap.String("host", target))
		}

		qos := *currentDSCP
		if remote.External {
			qos = ip.DSCPBeLow
		}

		for srcPort, rep := range r[(ip.GetDSCP).Pos(qos, logger)] {
			walkerF[0](rep, remote.Hostname, remote.Location, srcPort, foreground, logger)
		}
		if len(walkerF) > 1 {
			logger.Error("only one result walker function expected currently")
		}
	}
}

// processResults calculates metrics, uploads stats and stores in results[] for stdout, if needed.
func (rs resultStore) processResults(
	gl *config.Global,
	remotes config.RemoteStore,
	target string,
	req tcp.Message,
	rep tcp.Message,
	logger *log.Logger,
) report {

	// Calculate metrics
	l2w := rep.Ts.Run.Sub(req.Ts.Run)
	timedOut := l2w > gl.RemoteConfig.Timeout
	if timedOut {
		logger.Debug("Received timed-out echo response from", zap.String("target", target))
	}

	l1w := rep.Ts.Payload.Sub(req.Ts.Unix)
	if rep.FromExternalTarget(gl.RemoteConfig.TargetTCPPort) {
		l1w = -1
	}

	r := report{
		latency2Way: l2w,
		latency1Way: l1w,
		timedOut:    timedOut}

	// Store processed report to 'result' data structure for stdout, if needed
	if !*(gl.CLI.SenderOnlyMode) {
		QosDSCPIndex := (ip.GetDSCP).Pos(req.QosDSCP, logger)
		rs.add(target, QosDSCPIndex, req.SrcPort, r)
	}

	return r
}

func (rs resultStore) printResults(
	gl *config.Global,
	remotes config.RemoteStore,
	currentDSCP *ip.DSCPValue,
	logger *log.Logger,
) {
	foreground := *gl.CLI.Foreground

	printTableHeader(gl, (*currentDSCP).Text(logger), logger)
	rs.walkResults(remotes, currentDSCP, foreground, logger, printTableEntry)
	printTableFooter(foreground, logger)
}

// Run processes the echoes sent and received to compute and report all the metrics desired.
func Run(
	gl *config.Global,
	sentC chan tcp.Message,
	rcvdC chan tcp.Message,
	remotes config.RemoteStore,
	currentDSCP *ip.DSCPValue,
	sr metrics.Reporter,
	completeCycleUpload chan bool,
	wg *sync.WaitGroup,
	kill chan struct{},
	logger *log.Logger,
) {
	go func() {
		for {
			logger.Debug("Entering new batch cycle collection.")

			// Have garbage collector clean messageStore and resultStore after every bach cycle interval
			ms := make(messageStore)
			rs := make(resultStore)

			batchWorker(gl, sentC, rcvdC, remotes, ms, rs, currentDSCP, statsUpload, sr,
				completeCycleUpload, kill, wg, logger)
			logger.Debug("Removing all state from current batch cycle collection.")

			select {
			case <-kill:
				logger.Debug("Collector goroutine returning.")
				return
			default:
			}
		}
	}()
}

func batchWorker(
	gl *config.Global,
	sentC chan tcp.Message,
	rcvdC chan tcp.Message,
	remotes config.RemoteStore,
	ms messageStore,
	rs resultStore,
	currentDSCP *ip.DSCPValue,
	sfn statsUploader,
	sr metrics.Reporter,
	completeCycleUpload chan bool,
	kill chan struct{},
	wg *sync.WaitGroup,
	logger *log.Logger,
) {
	for {

		select {
		case out := <-sentC:
			if out.Type != tcp.EchoRequest {
				logger.Error("unexpected 'echo' type received in 'out' by collector.",
					zap.Any("type", out.Type))
				continue
			}
			QosDSCPIndex := (ip.GetDSCP).Pos(out.QosDSCP, logger)

			// SYN sent
			targetKey := out.DstAddr.String()
			ms.sentAdd(targetKey, QosDSCPIndex, out.SrcPort, out)

			// Matching SYN ACK already received?
			matchedMsg, existsMatch := ms.existsRcvd(targetKey, QosDSCPIndex, out.SrcPort)
			if existsMatch && matchedMsg.Type == tcp.EchoReply && matchedMsg.Ack == out.Seq+1 {
				logger.Debug("response already exists for same target",
					zap.Any("message", matchedMsg))

				report := rs.processResults(gl, remotes, targetKey, out, matchedMsg, logger)
				sfn(gl.RemoteConfig, sr, targetKey, remotes, out.QosDSCP, out.SrcPort, &report, logger)
			}

		case in := <-rcvdC:
			if in.Type != tcp.EchoReply {
				logger.Error("unexpected 'echo' type received in 'in' by collector.",
					zap.Any("type", in.Type))
				continue
			}
			QosDSCPIndex := (ip.GetDSCP).Pos(in.QosDSCP, logger)

			// SYN+ACK received
			targetKey := in.SrcAddr.String()
			ms.rcvdAdd(targetKey, QosDSCPIndex, in.SrcPort, in)

			// SYN+ACK received from internal target/agent
			// SrcPort = source port of pkt received by external target/server
			// DstPort = to the well-defined arachne port
			portKey := in.SrcPort
			if in.FromExternalTarget(gl.RemoteConfig.TargetTCPPort) {
				// SYN+ACK received from external target/server
				// SrcPort = not well-defined arachne port (e.g. 80)
				// DstPort = source port of pkt received by external target/server
				portKey = in.DstPort
			}

			// Matching SYN probe exists in sent and intended targets (remotes)?
			probe, existsMatch := ms.existsSent(targetKey, QosDSCPIndex, portKey)
			if !existsMatch {
				u := "target"
				if _, existsTarget := remotes[targetKey]; existsTarget {
					u = "probe"
				}
				logger.Debug("received following response",
					zap.String("non-existing", u),
					zap.Any("response", ms[targetKey][QosDSCPIndex].rcvd[in.SrcPort]),
					zap.String("source_address", targetKey))
				continue
			}

			if in.Ack != probe.Seq+1 {
				logger.Warn("unmatched ACK",
					zap.Uint32("in_ACK", in.Ack),
					zap.Uint32("out_SEQ", probe.Seq),
					zap.String("source_address", in.SrcAddr.String()))
				continue
			}
			report := rs.processResults(gl, remotes, targetKey, probe, in, logger)
			sfn(gl.RemoteConfig, sr, targetKey, remotes, in.QosDSCP, portKey, &report, logger)

		case <-completeCycleUpload:
			for key, value := range ms {
				logger.Debug("At end of batch cycle, sent and received 'messages' of",
					zap.String("host", key),
					zap.Any("messages", value))
			}

			for key, value := range rs {
				logger.Debug("At end of batch cycle, 'result' of",
					zap.String("host", key),
					zap.Any("result", value))
			}

			if !*gl.CLI.SenderOnlyMode {
				zeroOutResults(gl.RemoteConfig, ms, rs, remotes, sfn, sr, logger)

				//TODO print only tcp.DSCPBeLow when only external targets exist in remotes?
				rs.printResults(gl, remotes, currentDSCP, logger)
			}
			wg.Done()
			return
		case <-kill:
			logger.Info("Collector asked to exit without uploading.")
			return
		}
	}
}

type statsUploader func(
	glr *config.RemoteConfig,
	sr metrics.Reporter,
	target string,
	remotes config.RemoteStore,
	QOSDSCP ip.DSCPValue,
	srcPort layers.TCPPort,
	r *report,
	logger *log.Logger,
)

func statsUpload(
	glr *config.RemoteConfig,
	sr metrics.Reporter,
	target string,
	remotes config.RemoteStore,
	QOSDSCP ip.DSCPValue,
	srcPort layers.TCPPort,
	r *report,
	logger *log.Logger,
) {
	remote, existsTarget := remotes[target]
	if !existsTarget {
		logger.Error("host exists in resultStore, but not in remoteStore",
			zap.String("host", target))
		return
	}

	tags := map[string]string{
		"host":            glr.HostName,
		"host_location":   glr.Location,
		"target":          remote.Hostname,
		"target_location": remote.Location,
		"dscp":            strconv.Itoa(int(QOSDSCP)),
		"source_port":     strconv.Itoa(int(srcPort)),
		"timed_out":       strconv.FormatBool((*r).timedOut),
	}

	// Both following in nanoseconds
	sr.ReportGauge("latency_2way", tags, int64((*r).latency2Way))
	sr.ReportGauge("latency_1way", tags, (*r).latency1Way.Nanoseconds())

}

// zeroOutResults fills latencies for targets not existing in resultStore with zeros.
func zeroOutResults(
	glr *config.RemoteConfig,
	ms messageStore,
	rs resultStore,
	remotes config.RemoteStore,
	sfn statsUploader,
	sr metrics.Reporter,
	logger *log.Logger,
) {
	timedOutReport := report{
		latency2Way: 0,
		latency1Way: 0,
		timedOut:    true}

	for targetKey := range ms {
		_, existsTarget := rs[targetKey]
		if !existsTarget {
			var resDSCP [defines.NumQOSDCSPValues]map[layers.TCPPort]report
			rs[targetKey] = &resDSCP
		}
		for qosDSCP := 0; qosDSCP < defines.NumQOSDCSPValues; qosDSCP++ {
			if rs[targetKey][qosDSCP] == nil {
				rs[targetKey][qosDSCP] = make(map[layers.TCPPort]report)
			}
			for srcPort := range ms[targetKey][qosDSCP].sent {
				if _, existsSrc := rs[targetKey][qosDSCP][srcPort]; existsSrc {
					continue
				}
				rs[targetKey][qosDSCP][srcPort] = timedOutReport

				// Upload timed out results
				sfn(glr, sr, targetKey, remotes, ip.GetDSCP[qosDSCP], srcPort, &timedOutReport, logger)
				time.Sleep(1 * time.Millisecond)
			}
		}
	}
}

func printTableHeader(gl *config.Global, currentDSCP string, logger *log.Logger) {
	color.Set(color.FgHiYellow, color.Bold)
	defer color.Unset()

	if *gl.CLI.Foreground {
		fmt.Printf("%74s\n", "Arachne ["+defines.ArachneVersion+"]")
		fmt.Printf("%-55s%64s\n",
			gl.RemoteConfig.HostName+":"+strconv.Itoa(int(gl.RemoteConfig.TargetTCPPort))+
				" with QoS DSCP '"+currentDSCP+"'", time.Now().Format(time.RFC850))
		if gl.RemoteConfig.Location != "" && gl.RemoteConfig.Location != " " {
			fmt.Printf("Location: %s\n", gl.RemoteConfig.Location)
		}

		fmt.Printf("\n%51s|%26s|%8s%s%8s|\n", "", "", "", "RTT (msec)", "")
		fmt.Printf("Host%47s|%8s%s%10s|%4s%s%7s%s%5s|%2s%s\n", "",
			"", "Location", "",
			"", "2-way", "", "1-way", "",
			"", "Timed Out?")
		color.Set(color.FgHiYellow)
		fmt.Printf(strings.Repeat("-", hostWidth) + "|" +
			strings.Repeat("-", 26) + "|" +
			strings.Repeat("-", 26) + "|" +
			strings.Repeat("-", 13) + "\n")
	} else {
		logger.Info("Arachne -- Table of Results",
			zap.String("version", defines.ArachneVersion),
			zap.String("host", gl.RemoteConfig.HostName),
			zap.String("host_location", gl.RemoteConfig.Location),
			zap.Any("target_TCP_port", gl.RemoteConfig.TargetTCPPort),
			zap.String("QoS_DSCP", currentDSCP),
		)
	}
}

func printTableFooter(foreground bool, logger *log.Logger) {
	color.Set(color.FgHiYellow)
	defer color.Unset()

	if foreground {
		fmt.Printf(strings.Repeat("-", tableWidth) + "\n")
	} else {
		logger.Info(strings.Repeat("-", tableWidth))
	}
}

func printTableEntry(
	r report,
	targetHost string,
	targetLocation string,
	srcPort layers.TCPPort,
	foreground bool,
	logger *log.Logger,
) {
	var twoWay, oneWay zapcore.Field

	color.Set(color.FgHiYellow)
	defer color.Unset()

	timedOut := "no"
	if r.timedOut {
		timedOut = "yes"
	}
	if foreground {
		fmt.Printf("%-51s|", targetHost+"("+strconv.Itoa(int(srcPort))+")")
		fmt.Printf("%-26s|%3s", " "+targetLocation, "")
	}

	if r.latency2Way == 0 {
		twoWay = zap.String("2-way", "-")
		oneWay = zap.String("1-way", "-")
		if foreground {
			fmt.Printf("%4s %11s%8s%5s%s\n", "-", "-", "|", "", timedOut)
		}
	} else {
		twoWay = zap.Float64("2-way", float64(r.latency2Way/1e5)/10.0)
		// Ignore 1-way when echoing an external server or when estimated value is smaller than a threshold
		if r.latency1Way == -1 || r.latency1Way < 10*time.Nanosecond {
			if foreground {
				fmt.Printf("%5.1f %11s%7s%5s%s\n", float32(r.latency2Way/1e5)/10.0,
					"N/A", "|", "", timedOut)
			}
			oneWay = zap.String("1-way", "N/A")
		} else {
			if foreground {
				fmt.Printf("%5.1f %11.1f%7s%5s%s\n", float32(r.latency2Way/1e5)/10.0,
					float32(r.latency1Way/1e5)/10.0, "|", "", timedOut)
			}
			oneWay = zap.Float64("1-way", float64(r.latency1Way/1e5)/10.0/10.0)
		}
	}

	if !foreground {
		logger.Info("Result",
			zap.String("target", targetHost),
			zap.String("target_location", targetLocation),
			zap.Any("source_port", srcPort),
			twoWay,
			oneWay,
			zap.String("timed_out", timedOut))
	}
}
