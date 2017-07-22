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
	"math/rand"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/ip"
	"github.com/uber/arachne/internal/log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
type PortRange [2]layers.TCPPort

// Contains returns true if p is included within the PortRange t.
func (t PortRange) Contains(p layers.TCPPort) bool {
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

// Message is filled with the info about the 'echo' request sent or 'echo' reply received and
// emitted onto the 'sent' and 'rcvd' channels, respectively, for further processing by the collector.
type Message struct {
	Type    echoType
	SrcAddr net.IP
	DstAddr net.IP
	Af      int
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
	QosDSCP ip.DSCPValue
	Ts      Timestamp
	Seq     uint32
	Ack     uint32
}

// FromExternalTarget returns true if message has been received from external server and not an arachne agent.
func (m Message) FromExternalTarget(servicePort layers.TCPPort) bool {
	return m.DstPort != servicePort
}

// Timestamp holds all the different types of time stamps.
type Timestamp struct {
	Unix    time.Time
	Run     time.Time
	Payload time.Time
}

var (
	monoNow = monotime.Now
	timeNow = time.Now
)

// parsePktTCP extracts the TCP header layer and payload from an incoming packet.
func parsePktTCP(pkt gopacket.Packet) (layers.TCP, time.Time, error) {
	layer := pkt.Layer(layers.LayerTypeTCP)
	if layer == nil {
		return layers.TCP{}, time.Time{}, errors.New("invalid TCP layer")
	}
	tcpSegment := layer.(*layers.TCP)

	var payload time.Time
	if len(tcpSegment.Payload) >= defines.TimestampPayloadLengthBytes {
		ts := append([]byte(nil), tcpSegment.Payload[:defines.TimestampPayloadLengthBytes]...)
		if err := payload.UnmarshalBinary(ts); err != nil {
			return *tcpSegment, time.Time{}, err
		}
	}

	return *tcpSegment, payload, nil
}

// parsePktIP parses the IP header of an incoming packet and extracts the src IP addr and DSCP value.
func parsePktIP(pkt gopacket.Packet) (net.IP, ip.DSCPValue, error) {
	switch pkt.NetworkLayer().LayerType() {
	case layers.LayerTypeIPv4:
		layer := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if layer == nil {
			return net.IPv4zero, ip.DSCPValue(0), errors.New("layer type IPv4 invalid")
		}
		return layer.SrcIP, ip.DSCPValue(layer.TOS), nil
	case layers.LayerTypeIPv6:
		layer := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if layer == nil {
			return net.IPv6zero, ip.DSCPValue(0), errors.New("layer type IPv6 invalid")
		}
		return layer.SrcIP, ip.DSCPValue(layer.TrafficClass), nil
	}

	return net.IPv4zero, ip.DSCPValue(0), errors.New("unknown network layer type")
}

// optsTCP contains the gopacket serialization options for the TCP layer
var optsTCP = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

// makePkt creates and serializes a TCP Echo.
func makePkt(
	af int,
	srcAddr net.IP,
	dstAddr net.IP,
	srcPort layers.TCPPort,
	dstPort layers.TCPPort,
	dscpv ip.DSCPValue,
	flags tcpFlags,
	seqNum uint32,
	ackNum uint32,
) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()

	// gopacket serialization options for IP header are OS specific
	optsIP := ip.GetIPLayerOptions()

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
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Seq:        seqNum,
		Ack:        ackNum,
		DataOffset: uint8(defines.TCPHeaderLength / 4), // TCP Header size in 32-bit words
		SYN:        flags.syn,
		RST:        flags.rst,
		ACK:        flags.ack,
		Window:     defines.TCPWindowSize,
		Checksum:   0, // computed upon serialization
	}

	// Length of TCP portion is payload length + fixed 20 bytes for Header
	tcpLen := defines.TCPHeaderLength + len(buf.Bytes())

	ipLayer, err := ip.GetIPHeaderLayer(af, dscpv, uint16(tcpLen), srcAddr, dstAddr)
	if err != nil {
		return nil, err
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	if err = tcpLayer.SerializeTo(buf, optsTCP); err != nil {
		return nil, err
	}

	switch layer := ipLayer.(type) {
	case *layers.IPv4:
		err = layer.SerializeTo(buf, optsIP)
	case *layers.IPv6:
		err = layer.SerializeTo(buf, optsIP)
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
				logger.Error("error parsing packet IP layer", zap.Error(err), zap.Any("packet", pkt))
				continue
			}

			tcpHeader, payloadTime, err := parsePktTCP(pkt)
			if err != nil {
				logger.Error("error parsing packet TCP layer", zap.Error(err), zap.Any("packet", pkt))
				continue
			}

			switch {
			case tcpHeader.SYN && !tcpHeader.ACK:
				// Received SYN (Open port)
				logger.Debug("Received",
					zap.String("flag", "SYN"),
					zap.Stringer("src_address", srcIP),
					zap.Any("src_port", tcpHeader.SrcPort))

				// Replying with SYN+ACK to Arachne agent
				srcPortRange := PortRange{tcpHeader.SrcPort, tcpHeader.SrcPort}
				seqNum := rand.Uint32()
				ackNum := tcpHeader.Seq + 1
				flags := tcpFlags{syn: true, ack: true}
				// Replies are sent to the same port as the one this agent is listening on
				if err := send(conn, &srcIP, conn.ListenPort, srcPortRange, DSCPv,
					flags, seqNum, ackNum, sentC, kill, logger); err != nil {
					logger.Error("failed to send SYN-ACK", zap.Error(err))
				}

			case tcpHeader.SYN && tcpHeader.ACK:
				// Received SYN+ACK (Open port)
				logger.Debug("Received",
					zap.String("flag", "SYN ACK"),
					zap.Stringer("src_address", srcIP),
					zap.Any("src_port", tcpHeader.SrcPort))

				inMsg := Message{
					Type:    EchoReply,
					SrcAddr: srcIP,
					DstAddr: conn.SrcAddr,
					Af:      conn.AF,
					SrcPort: tcpHeader.SrcPort,
					DstPort: tcpHeader.DstPort,
					QosDSCP: DSCPv,
					Ts: Timestamp{
						Run:     receiveTime,
						Payload: payloadTime,
					},
					Seq: tcpHeader.Seq,
					Ack: tcpHeader.Ack,
				}
				// Send 'echo' reply message received to collector
				in <- inMsg

				if inMsg.FromExternalTarget(conn.ListenPort) {
					//TODO verify
					// Replying with RST only to external target
					srcPortRange := PortRange{tcpHeader.SrcPort, tcpHeader.SrcPort}
					seqNum := tcpHeader.Ack
					ackNum := tcpHeader.Seq + 1
					flags := tcpFlags{rst: true}
					err = send(conn, &srcIP, defines.PortHTTPS, srcPortRange,
						ip.DSCPBeLow, flags, seqNum, ackNum, sentC, kill, logger)
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
	targetPort layers.TCPPort,
	srcPortRange PortRange,
	QoSEnabled bool,
	currentDSCP *ip.DSCPValue,
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
			for i := range ip.GetDSCP {
				t0 := time.Now()
				if !QoSEnabled {
					*currentDSCP = ip.GetDSCP[0]
				} else {
					*currentDSCP = ip.GetDSCP[i]
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
	targetPort layers.TCPPort,
	srcPortRange PortRange,
	DSCPv ip.DSCPValue,
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
			qos = ip.DSCPBeLow
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
	targetPort layers.TCPPort,
	srcPortRange PortRange,
	DSCPv ip.DSCPValue,
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
				zap.Any("src_port", srcPort),
				zap.String("dst_address", dstAddr.String()),
				zap.Any("dst_port", targetPort)}

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
