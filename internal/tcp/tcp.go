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
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/ip"
	"github.com/uber/arachne/internal/log"

	"github.com/pkg/errors"
	"github.com/spacemonkeygo/monotime"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type tcpFlags struct {
	fin, syn, rst, psh, ack, urg, ece, cwr, ns bool
}

type echoType uint8

// PortRange is the inclusive range of src ports.
type PortRange [2]uint16

// Contains returns true if p is included within the PortRange t.
func (t PortRange) Contains(p uint16) bool {
	return p >= t[0] && p <= t[1]
}

//go:generatestringer­type=EchoType

// 'Echo' Types
const (
	EchoRequest echoType = iota + 1
	EchoReply
)

func (q echoType) text(logger *log.Logger) string {
	switch q {
	case EchoRequest:
		return "Echo Request"
	case EchoReply:
		return "Echo Reply"
	default:
		logger.Fatal("unhandled Echo type family", zap.Any("echo_type", q))
	}
	return "" // unreachable
}

const tcpHdrSize int = 20 // 20 bytes without any TCP Options

// Message is filled with the info about the 'echo' request sent or 'echo' reply received and
// emitted onto the 'sent' and 'rcvd' channels, respectively, for further processing by the collector.
type Message struct {
	Type    echoType
	SrcAddr net.IP
	DstAddr net.IP
	Af      int
	SrcPort uint16
	DstPort uint16
	QosDSCP DSCPValue
	Ts      Timestamp
	Seq     uint32
	Ack     uint32
}

// Timestamp holds all the different types of time stamps.
type Timestamp struct {
	Unix    time.Time
	Run     time.Time
	Payload time.Time
}

// DSCPValue represents a QoS DSCP value.
type DSCPValue uint8

// QoS DSCP values mapped to TOS.
const (
	DSCPBeLow     DSCPValue = 0   // 000000 BE
	DSCPBeHigh    DSCPValue = 4   // 000001 BE
	DSCPBulkLow   DSCPValue = 40  // 001010 AF11
	DSCPBulkHigh  DSCPValue = 56  // 001110 AF13
	DSCPTier2Low  DSCPValue = 72  // 010010 AF21
	DSCPTier2High DSCPValue = 88  // 010110 AF23
	DSCPTier1Low  DSCPValue = 104 // 011010 AF31
	DSCPTier1High DSCPValue = 120 // 011110 AF33
	DSCPTier0Low  DSCPValue = 160 // 101000 EF
	DSCPNc6       DSCPValue = 192 // 110000 CS6
	DSCPNc7       DSCPValue = 224 // 111000 CS7
)

// GetDSCP holds all the DSCP values in a slice.
var GetDSCP = DSCPSlice{
	DSCPBeLow,
	DSCPBeHigh,
	DSCPBulkLow,
	DSCPBulkHigh,
	DSCPTier2Low,
	DSCPTier2High,
	DSCPTier1Low,
	DSCPTier1High,
	DSCPTier0Low,
	DSCPNc6,
	DSCPNc7,
}

// DSCPSlice represents a slice of DSCP values.
type DSCPSlice []DSCPValue

// Pos returns the index of the DSCP value in the DSCPSlice, not the actual DSCP value.
func (slice DSCPSlice) Pos(value DSCPValue, logger *log.Logger) uint8 {

	for p, v := range slice {
		if v == value {
			return uint8(p)
		}
	}
	logger.Warn("QoS DSCP value not matching one of supported classes",
		zap.Any("DSCP_value", value),
		zap.String("supported_classes", fmt.Sprintf("%v", slice)))
	return 0
}

// Text provides the text description of the DSCPValue.
func (q DSCPValue) Text(logger *log.Logger) string {
	switch q {
	case DSCPBeLow:
		return "BE low"
	case DSCPBeHigh:
		return "BE high"
	case DSCPBulkLow:
		return "AF11"
	case DSCPBulkHigh:
		return "AF113"
	case DSCPTier2Low:
		return "AF21"
	case DSCPTier2High:
		return "AF23"
	case DSCPTier1Low:
		return "AF31"
	case DSCPTier1High:
		return "AF33"
	case DSCPTier0Low:
		return "EF"
	case DSCPNc6:
		return "CS6"
	case DSCPNc7:
		return "CS7"
	default:
		logger.Error("unhandled QoS DSCP value", zap.Any("DSCP_value", q))
		return "unknown"
	}
}

// FromExternalTarget returns true if message has been received from external server and not an arachne agent.
func (m Message) FromExternalTarget(servicePort uint16) bool {
	return m.DstPort != servicePort
}

var (
	monoNow = monotime.Now
	timeNow = time.Now
)

// parsePktTCP extracts the TCP header layer and payload from an incoming packet.
func parsePktTCP(pkt gopacket.Packet) (tcpHeader layers.TCP, payload time.Time, err error) {
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcp == nil {
		err = errors.New("Invalid TCP Layer")
		return
	}
	tcpHeader = *tcp

	if len(tcp.Payload) >= defines.TimestampPayloadLengthBytes {
		ts := append([]byte(nil), tcp.Payload[:defines.TimestampPayloadLengthBytes]...)
		err = payload.UnmarshalBinary(ts)
	}

	return
}

// parsePktIP parses the IP header of an incoming packet and extracts the src IP addr and DSCP value.
func parsePktIP(pkt gopacket.Packet) (srcIP net.IP, dscpv DSCPValue, err error) {
	switch pkt.NetworkLayer().LayerType() {
	case layers.LayerTypeIPv4:
		ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ip == nil {
			err = errors.New("Invalid IPv4 Layer")
			return
		}
		srcIP = ip.SrcIP
		dscpv = DSCPValue(ip.TOS)
	case layers.LayerTypeIPv6:
		ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if ip == nil {
			err = errors.New("Invalid IPv6 Layer")
			return
		}
		srcIP = ip.SrcIP
		dscpv = DSCPValue(ip.TrafficClass)
	}
	return
}

// makePkt creates and serializes a TCP Echo.
func makePkt(
	af int,
	srcAddr net.IP,
	dstAddr net.IP,
	srcPort uint16,
	dstPort uint16,
	dscpv DSCPValue,
	flags tcpFlags,
	seqNum uint32,
	ackNum uint32,
) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()

	// gopacket serialization options for IP header are OS specific
	optsIP := ip.GetIPLayerOptions()
	optsTCP := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// When replying with SYN+ACK, a time-stamped payload is included
	if flags.syn != false && flags.ack != false {
		payloadTime, err := timeNow().MarshalBinary()
		if err != nil {
			return nil, err
		}
		payloadLayer := gopacket.Payload(payloadTime)
		payloadLayer.SerializeTo(buf, optsTCP)
	}

	tcpLayer := &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seqNum,
		Ack:        ackNum,
		DataOffset: uint8(tcpHdrSize / 4), // TCP Header size in 32-bit words
		SYN:        flags.syn,
		RST:        flags.rst,
		ACK:        flags.ack,
		Window:     defines.TCPWindowSize,
		Checksum:   0, // computed upon serialization
	}

	// Length of TCP portion is payload length + fixed 20 bytes for Header
	tcpLen := tcpHdrSize + len(buf.Bytes())

	ipLayer, err := ip.GetIPHeaderLayer(af, uint8(dscpv), uint16(tcpLen), srcAddr, dstAddr)
	if err != nil {
		return nil, err
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	if err = tcpLayer.SerializeTo(buf, optsTCP); err != nil {
		return nil, err
	}

	switch ipLayer.(type) {
	case *layers.IPv4:
		err = ipLayer.(*layers.IPv4).SerializeTo(buf, optsIP)
	case *layers.IPv6:
		err = ipLayer.(*layers.IPv6).SerializeTo(buf, optsIP)
	}
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Receiver checks if the incoming packet is actually a response to our probe and acts accordingly.
//TODO Test IPv6
func Receiver(
	conn *ip.Conn,
	listenPort uint16,
	sentC chan Message,
	rcvdC chan Message,
	kill chan struct{},
	logger *log.Logger,
) error {
	var receiveTime time.Time

	logger.Info("TCP receiver starting...", zap.Int("AF", conn.AF))

	// IP + TCP header, this channel is fed from the socket
	in := make(chan Message, defines.ChannelInBufferSize)

	go func() {
		defer close(in)

		for {
			pkt, err := conn.NextPacket()
			// parent has closed the socket likely
			if err != nil {
				logger.Fatal("failed to receive packet from packet source",
					zap.Error(err))
			}
			receiveTime = monoNow()

			srcIP, DSCPv, err := parsePktIP(pkt)
			if err != nil {
				logger.Error("Error parsing packet IP layer", zap.Error(err), zap.Any("packet", pkt))
				continue
			}

			tcpHeader, payloadTime, err := parsePktTCP(pkt)
			if err != nil {
				logger.Error("Error parsing packet TCP layer", zap.Error(err), zap.Any("packet", pkt))
				continue
			}

			fromAddrStr := srcIP.String()
			switch {
			case tcpHeader.SYN && !tcpHeader.ACK:
				// Received SYN (Open port)
				logger.Debug("Received",
					zap.String("flag", "SYN"),
					zap.String("src_address", fromAddrStr),
					zap.Uint16("src_port", uint16(tcpHeader.SrcPort)))

				// Replying with SYN+ACK to Arachne agent
				srcPortRange := PortRange{uint16(tcpHeader.SrcPort), uint16(tcpHeader.SrcPort)}
				seqNum := rand.Uint32()
				ackNum := tcpHeader.Seq + 1
				flags := tcpFlags{syn: true, ack: true}
				if err = send(conn, &srcIP, listenPort, srcPortRange, DSCPv,
					flags, seqNum, ackNum, sentC, kill, logger); err != nil {
					logger.Error("failed to send SYN-ACK", zap.Error(err))
				}

			case tcpHeader.SYN && tcpHeader.ACK:
				// Received SYN+ACK (Open port)
				logger.Debug("Received",
					zap.String("flag", "SYN ACK"),
					zap.String("src_address", fromAddrStr),
					zap.Uint16("src_port", uint16(tcpHeader.SrcPort)))

				inMsg := Message{
					Type:    EchoReply,
					SrcAddr: srcIP,
					DstAddr: conn.SrcAddr,
					Af:      conn.AF,
					SrcPort: uint16(tcpHeader.SrcPort),
					DstPort: uint16(tcpHeader.DstPort),
					QosDSCP: DSCPv,
					Ts: Timestamp{
						Run:     receiveTime,
						Payload: payloadTime},
					Seq: tcpHeader.Seq,
					Ack: tcpHeader.Ack,
				}
				// Send 'echo' reply message received to collector
				in <- inMsg

				if inMsg.FromExternalTarget(listenPort) {
					//TODO verify
					// Replying with RST only to external target
					srcPortRange := PortRange{uint16(tcpHeader.SrcPort), uint16(tcpHeader.SrcPort)}
					seqNum := tcpHeader.Ack
					ackNum := tcpHeader.Seq + 1
					flags := tcpFlags{rst: true}
					err = send(conn, &srcIP, defines.PortHTTPS, srcPortRange,
						DSCPBeLow, flags, seqNum, ackNum, sentC, kill, logger)
					if err != nil {
						logger.Error("failed to send RST", zap.Error(err))
					}
				}
			}

			select {
			case <-kill:
				logger.Info("TCP receiver terminating...", zap.Int("AF", conn.AF))
				return
			default:
				continue
			}
		}
	}()

	go func() {
		for {
			select {
			case reply := <-in:
				rcvdC <- reply
			case <-kill:
				logger.Info("'rcvdC' channel goroutine returning.")
				return
			}
		}
	}()

	return nil
}

// EchoTargets sends echoes (SYNs) to all targets included in 'remotes.'
func EchoTargets(
	remotes interface{},
	conn *ip.Conn,
	targetPort uint16,
	srcPortRange PortRange,
	QoSEnabled bool,
	currentDSCP *DSCPValue,
	realBatchInterval time.Duration,
	batchEndCycle *time.Ticker,
	sentC chan Message,
	senderOnlyMode bool,
	completeCycleUpload chan bool,
	finishedCycleUpload *sync.WaitGroup,
	kill chan struct{},
	logger *log.Logger,
) {
	go func() {
		for {
			for i := range GetDSCP {
				t0 := time.Now()
				if !QoSEnabled {
					*currentDSCP = GetDSCP[0]
				} else {
					*currentDSCP = GetDSCP[i]
				}
				echoTargetsWorker(remotes, conn, targetPort, srcPortRange, *currentDSCP,
					realBatchInterval, batchEndCycle, sentC, kill, logger)
				select {
				case <-kill:
					//Stop the batch cycle Ticker.
					batchEndCycle.Stop()
					return
				case <-batchEndCycle.C:
					if !(senderOnlyMode) {
						finishedCycleUpload.Add(1)
						// Request from Collector to complete all stats uploads for this
						// batch cycle
						completeCycleUpload <- true
						// Wait till the above request is fulfilled
						finishedCycleUpload.Wait()
						t1 := time.Now()
						logger.Debug("Completed echoing and uploading all "+
							"stats of current batch cycle",
							zap.String("duration", t1.Sub(t0).String()))
						continue
					}
					t1 := time.Now()
					logger.Debug("Completed echoing current batch cycle",
						zap.String("duration", t1.Sub(t0).String()))
					continue
				}
			}
		}
	}()
}

func echoTargetsWorker(
	remotes interface{},
	conn *ip.Conn,
	targetPort uint16,
	srcPortRange PortRange,
	DSCPv DSCPValue,
	realBatchInterval time.Duration,
	batchEndCycle *time.Ticker,
	sentC chan Message,
	kill chan struct{},
	logger *log.Logger,
) error {

	r := reflect.ValueOf(remotes)

	if r.Kind() != reflect.Map {
		return errors.New("remote interface not a map in echoTargetsWorker()")
	}

	// Echo interval is half the time of the 'real' batch interval
	echoInterval := time.Duration(int(realBatchInterval) / 2 / len(r.MapKeys()))
	tickCh := time.NewTicker(echoInterval)
	defer tickCh.Stop()

	for _, key := range r.MapKeys() {
		remoteStruct := r.MapIndex(key)
		if remoteStruct.Kind() != reflect.Struct {
			return errors.New("remote field not a struct in tcp.EchoTargets()")
		}
		dstAddr := net.IP(remoteStruct.FieldByName("IP").Bytes())
		ext := remoteStruct.FieldByName("External").Bool()

		// Send SYN with random SEQ
		flags := tcpFlags{syn: true}
		port := targetPort
		qos := DSCPv
		if ext {
			port = defines.PortHTTPS
			qos = DSCPBeLow
		}
		if err := send(conn, &dstAddr, port, srcPortRange, qos,
			flags, rand.Uint32(), 0, sentC, kill, logger); err != nil {
			return err
		}

		select {
		case <-tickCh.C:
			continue
		case <-batchEndCycle.C:
			return nil
		}
	}
	return nil
}

// Sender generates TCP packet probes with given TTL at given packet per second rate.
// The packet are injected into raw socket and their descriptions are published to the output channel as Probe messages.
//TODO Test IPv6
func send(
	conn *ip.Conn,
	dstAddr *net.IP,
	targetPort uint16,
	srcPortRange PortRange,
	DSCPv DSCPValue,
	ctrlFlags tcpFlags,
	seqNum uint32,
	ackNum uint32,
	sentC chan Message,
	kill chan struct{},
	logger *log.Logger,
) error {
	var flag string

	switch {
	case (ctrlFlags.syn != false) && (ctrlFlags.ack == false):
		flag = "SYN"
	case ctrlFlags.syn != false && (ctrlFlags.ack != false):
		flag = "SYN ACK"
	case ctrlFlags.rst != false:
		flag = "RST"
	default:
		flag = ""
	}

	go func() {
		rand.Seed(time.Now().UnixNano())
		for srcPort := srcPortRange[0]; srcPort <= srcPortRange[1]; srcPort++ {

			zf := []zapcore.Field{
				zap.String("flag", flag),
				zap.String("src_address", conn.SrcAddr.String()),
				zap.Uint16("src_port", srcPort),
				zap.String("dst_address", dstAddr.String()),
				zap.Uint16("dst_port", targetPort)}

			packet, err := makePkt(conn.AF, conn.SrcAddr, *dstAddr, srcPort, targetPort, DSCPv, ctrlFlags, seqNum, ackNum)
			if err != nil {
				logger.Error("error creating packet", zap.Error(err))
				goto cont
			}

			if err = conn.SendTo(packet, *dstAddr); err == nil {
				logger.Debug("Sent", zf...)
				if flag == "SYN" {
					// Send 'echo' request message to collector
					sentC <- Message{
						Type:    EchoRequest,
						SrcAddr: conn.SrcAddr,
						DstAddr: *dstAddr,
						Af:      conn.AF,
						SrcPort: srcPort,
						QosDSCP: DSCPv,
						Ts: Timestamp{
							Run:  monoNow(),
							Unix: timeNow()},
						Seq: seqNum,
						Ack: ackNum,
					}
				}
			} else {
				logger.Error("failed to send out", zf...)
			}

		cont:
			select {
			case <-kill:
				logger.Info("Sender requested to exit prematurely.",
					zap.String("destination", dstAddr.String()))
				return
			default:
				continue
			}
		}
	}()

	return nil
}
