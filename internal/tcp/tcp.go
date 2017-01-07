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
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/spacemonkeygo/monotime"
	"github.com/uber-go/zap"
	"github.com/uber/arachne/defines"
)

// TCP flags
const (
	fin uint8 = (1 << iota) // 00 0001
	syn                     // 00 0010
	rst                     // 00 0100
	psh                     // 00 1000
	ack                     // 01 0000
	urg                     // 10 0000
)

type echoType uint8

// PortRange is the inclusive range of src ports
type PortRange [2]uint16

// Contains returns true if p is included within the PortRange t
func (t PortRange) Contains(p uint16) bool {
	return p >= t[0] && p <= t[1]
}

//go:generatestringer­type=EchoType

// 'Echo' Types
const (
	EchoRequest echoType = iota + 1
	EchoReply
)

func (q echoType) text(logger zap.Logger) string {
	switch q {
	case EchoRequest:
		return "Echo Request"
	case EchoReply:
		return "Echo Reply"
	default:
		logger.Fatal("unhandled Echo type family", zap.Object("echo_type", q))
	}
	return "" // unreachable
}

const tcpHdrSize int = 20 // 20 bytes without any TCP Options
const maxTCPPacketSizeBytes int = 65 * 1024

type tcpPacket struct {
	tcpHeader
	tcpPayload
}

// Defines the TCP header struct
type tcpHeader struct {
	srcPort    uint16
	dstPort    uint16
	seqNum     uint32
	ackNum     uint32
	dataOffset uint8 // 4 bits
	reserved   uint8 // 3 bits
	ECN        uint8 // 3 bits
	ctrl       uint8 // 6 bits
	window     uint16
	checksum   uint16
	urgent     uint16
	options    []tcpOption
}

type tcpOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

// Defines the TCP payload struct
type tcpPayload struct {
	Ts time.Time
}

// Message is filled with the info about the 'echo' request sent or 'echo' reply received and
// emitted onto the 'sent' and 'rcvd' channels, respectively, for further processing by the collector.
type Message struct {
	Type    echoType
	SrcAddr net.IP
	DstAddr net.IP
	Af      string
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

// DSCPValue represents a QoS DSCP value
type DSCPValue uint8

// QoS DSCP values mapped to TOS
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

// GetDSCP holds all the DSCP values in a slice
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

// DSCPSlice represents a slice of DSCP values
type DSCPSlice []DSCPValue

// Pos returns the index of the DSCP value in the DSCPSlice, not the actual DSCP value
func (slice DSCPSlice) Pos(value DSCPValue, logger zap.Logger) uint8 {

	for p, v := range slice {
		if v == value {
			return uint8(p)
		}
	}
	logger.Error("QoS DSCP value not matching one of supported classes",
		zap.Object("DSCP_value", value),
		zap.String("supported_classes", fmt.Sprintf("%v", slice)))
	return 0
}

// Text provides the text description of the DSCPValue
func (q DSCPValue) Text(logger zap.Logger) string {
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
		logger.Error("unhandled QoS DSCP value", zap.Object("DSCP_value", q))
		return "unknown"
	}
}

// FromExternalTarget returns true if message has been received from external server and not an arachne agent
func (m Message) FromExternalTarget(servicePort uint16) bool {
	return m.DstPort != servicePort
}

var (
	monoNow = monotime.Now
	timeNow = time.Now
)

// Parse TCP Echo header from received packet
func parsePkt(data []byte, listenPort uint16) (*tcpPacket, bool) {
	var pkt tcpPacket

	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &pkt.srcPort)
	binary.Read(r, binary.BigEndian, &pkt.dstPort)

	if uint16(pkt.dstPort) != listenPort &&
		(uint16(pkt.srcPort) != defines.PortHTTP && uint16(pkt.srcPort) != defines.PortHTTPS) {
		return nil, false
	}
	binary.Read(r, binary.BigEndian, &pkt.seqNum)
	binary.Read(r, binary.BigEndian, &pkt.ackNum)

	var mix uint16
	binary.Read(r, binary.BigEndian, &mix)
	pkt.dataOffset = byte(mix >> 12)  // top 4 bits
	pkt.reserved = byte(mix >> 9 & 7) // 3 bits
	pkt.ECN = byte(mix >> 6 & 7)      // 3 bits
	pkt.ctrl = byte(mix & 0x3f)       // bottom 6 bits

	binary.Read(r, binary.BigEndian, &pkt.window)
	binary.Read(r, binary.BigEndian, &pkt.checksum)
	binary.Read(r, binary.BigEndian, &pkt.urgent)

	if pkt.dataOffset > 5 {
		binary.Read(r, binary.BigEndian, &pkt.options)
	}

	headerLen := pkt.dataOffset * 4
	if len(data) > int(headerLen) {
		ts := make([]byte, defines.TimestampPayloadLengthBytes)
		binary.Read(r, binary.BigEndian, &ts)

		var unByteTime time.Time
		if err := unByteTime.UnmarshalBinary(ts); err == nil {
			pkt.Ts = unByteTime
		}
	}

	return &pkt, true
}

// Create & serialize a TCP Echo
func makePkt(
	af string,
	srcAddr *net.IP,
	dstAddr *net.IP,
	srcPort uint16,
	dstPort uint16,
	flags uint8,
	seqNum uint32,
	ackNum uint32,
) ([]byte, error) {
	var err error
	packet := tcpPacket{
		tcpHeader{
			srcPort:    uint16(srcPort), // ephemeral port
			dstPort:    uint16(dstPort),
			seqNum:     seqNum,
			ackNum:     ackNum,
			dataOffset: uint8(5), // 4 bits
			reserved:   0,        // 3 bits
			ECN:        0,        // 3 bits
			ctrl:       flags,    // 6 bits (000010, SYN bit set)
			window:     0xaaaa,   // The amount of data that it is able to accept in bytes
			checksum:   0,        // Kernel will set this if it's 0
			urgent:     0,
			options:    []tcpOption{},
		},
		tcpPayload{},
	}

	// When replying with SYN+ACK, a time-stamped payload is included
	if flags&syn != 0 && flags&ack != 0 {
		packet.tcpPayload.Ts = timeNow()
	}
	bytes := packet.Marshal()
	packet.checksum, err = checksum(af, bytes, srcAddr, dstAddr)
	if err != nil {
		return nil, err
	}

	return packet.Marshal(), nil
}

// Marshal emits raw bytes for the packet
func (pkt *tcpPacket) Marshal() []byte {

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, pkt.srcPort)
	binary.Write(buf, binary.BigEndian, pkt.dstPort)
	binary.Write(buf, binary.BigEndian, pkt.seqNum)
	binary.Write(buf, binary.BigEndian, pkt.ackNum)

	var mix uint16
	mix = uint16(pkt.dataOffset)<<12 | // top 4 bits
		uint16(pkt.reserved)<<9 | // 3 bits
		uint16(pkt.ECN)<<6 | // 3 bits
		uint16(pkt.ctrl) // bottom 6 bits
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, pkt.window)
	binary.Write(buf, binary.BigEndian, pkt.checksum)
	binary.Write(buf, binary.BigEndian, pkt.urgent)

	for _, option := range pkt.options {
		binary.Write(buf, binary.BigEndian, option.Kind)
		if option.Length > 1 {
			binary.Write(buf, binary.BigEndian, option.Length)
			binary.Write(buf, binary.BigEndian, option.Data)
		}
	}

	if pkt.tcpPayload != (tcpPayload{}) {
		byteTime, err := pkt.tcpPayload.Ts.MarshalBinary()
		if err == nil {
			binary.Write(buf, binary.BigEndian, byteTime)
		}
	}

	out := buf.Bytes()

	return out
}

func (tcp *tcpHeader) hasFlag(flagBit byte) bool {
	return tcp.ctrl&flagBit != 0
}

// TCP Checksum
func checksum(af string, data []byte, srcip, dstip *net.IP) (uint16, error) {

	// the pseudo header used for TCP c-sum computation
	var pseudoHeader []byte

	pseudoHeader = append(pseudoHeader, *srcip...)
	pseudoHeader = append(pseudoHeader, *dstip...)
	switch af {
	case "ip4":
		pseudoHeader = append(pseudoHeader, []byte{
			0,
			6,                  // protocol number for TCP
			0, byte(len(data)), // TCP length (16 bits), w/o pseudoheader
		}...)
	case "ip6":
		pseudoHeader = append(pseudoHeader, []byte{
			0, 0, 0, byte(len(data)), // TCP length (32 bits), w/0 pseudoheader
			0, 0, 0,
			6, // protocol number for TCP
		}...)
	default:
		return 0, fmt.Errorf("unhandled AF family")
	}

	body := make([]byte, 0, len(pseudoHeader)+len(data))
	body = append(body, pseudoHeader...)
	body = append(body, data...)

	bodyLen := len(body)

	var word uint16
	var csum uint32

	for i := 0; i+1 < bodyLen; i += 2 {
		word = uint16(body[i])<<8 | uint16(body[i+1])
		csum += uint32(word)
	}

	if bodyLen%2 != 0 {
		csum += uint32(body[len(body)-1])
	}

	csum = (csum >> 16) + (csum & 0xffff)
	csum = csum + (csum >> 16)

	// Bitwise complement
	return uint16(^csum), nil
}

// Receiver checks if the incoming packet is actually a response to our probe and
// acts accordingly
//TODO Test IPv6
func Receiver(
	af string,
	srcAddr *net.IP,
	listenPort uint16,
	interfaceName string,
	sentC chan Message,
	rcvdC chan Message,
	kill chan struct{},
	logger zap.Logger,
) error {

	var (
		recvSocket  int
		ipHdrSize   int
		err         error
		receiveTime time.Time
	)

	logger.Info("TCP receiver starting...", zap.String("AF", af))

	// create the socket
	switch af {
	case "ip4":
		recvSocket, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
		// IPv4 header is always included with the ipv4 raw socket receive
		ipHdrSize = 20
	case "ip6":
		recvSocket, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
		// no IPv6 header present on TCP packets received on the raw socket
		ipHdrSize = 0
	default:
		return fmt.Errorf("unhandled AF family")
	}
	if err != nil {
		return fmt.Errorf("failed to create %s receive socket: %s", af, err)
	}

	if err := bindToDevice(recvSocket, interfaceName); err != nil {
		return fmt.Errorf("failed to bind %s receive socket to interface %s: %s", af, interfaceName, err)
	}

	// IP + TCP header, this channel is fed from the socket
	in := make(chan Message, defines.ChannelInBufferSize)

	go func() {
		defer syscall.Close(recvSocket)
		defer close(in)

		rawPacket := make([]byte, maxTCPPacketSizeBytes)
		for {
			n, from, err := syscall.Recvfrom(recvSocket, rawPacket, 0)
			// parent has closed the socket likely
			if err != nil {
				logger.Fatal("failed to receive from receiver socket",
					zap.String("AF", af),
					zap.Error(err))
			}
			receiveTime = monoNow()

			// IP + TCP header size
			if n < ipHdrSize+tcpHdrSize {
				logger.Fatal("n < ipHdrSize + tcpHdrSize",
					zap.Int("ipHdrSize", ipHdrSize),
					zap.Int("tcpHdrSize", tcpHdrSize))
			}

			pkt, destinedToArachne := parsePkt(rawPacket[ipHdrSize:], listenPort)
			if !destinedToArachne {
				continue
			}

			var DSCPv DSCPValue
			r := bytes.NewReader(rawPacket[1:2])
			binary.Read(r, binary.BigEndian, &DSCPv)
			if DSCPv < 0 {
				logger.Warn("Received packet with invalid QoS DSCP value",
					zap.Object("DSCP_value", DSCPv),
					zap.Object("raw_packet", rawPacket))
				continue
			}

			var fromAddr net.IP
			switch af {
			case "ip4":
				fromAddr = net.IP((from.(*syscall.SockaddrInet4).Addr)[:])
			case "ip6":
				fromAddr = net.IP((from.(*syscall.SockaddrInet6).Addr)[:])
			default:
				logger.Fatal("unhandled AF family", zap.String("AF", af))
			}
			fromAddrStr := fromAddr.String()
			logger := logger.With(zap.String("address", fromAddrStr))

			switch {
			case pkt.hasFlag(syn) && !pkt.hasFlag(ack):
				// Received SYN (Open port)
				logger.Debug("Received",
					zap.String("flag", "SYN"),
					zap.Object("port", pkt.dstPort))

				// Replying with SYN+ACK to Arachne agent
				srcPortRange := PortRange{pkt.srcPort, pkt.srcPort}
				seqNum := rand.Uint32()
				ackNum := pkt.seqNum + 1
				err = send(af, srcAddr, &fromAddr, listenPort, srcPortRange, DSCPv,
					syn|ack, seqNum, ackNum, sentC, kill, logger)
				if err != nil {
					logger.Fatal("failed to send SYN-ACK", zap.Error(err))
				}

			case pkt.hasFlag(syn) && pkt.hasFlag(ack):
				// Received SYN+ACK (Open port)
				logger.Debug("Received",
					zap.String("flag", "SYN ACK"),
					zap.Object("port", pkt.srcPort))

				inMsg := Message{
					Type:    EchoReply,
					SrcAddr: fromAddr,
					DstAddr: *srcAddr,
					Af:      af,
					SrcPort: uint16(pkt.srcPort),
					DstPort: uint16(pkt.dstPort),
					QosDSCP: DSCPv,
					Ts: Timestamp{
						Run:     receiveTime,
						Payload: pkt.tcpPayload.Ts},
					Seq: pkt.seqNum,
					Ack: pkt.ackNum,
				}
				// Send 'echo' reply message received to collector
				in <- inMsg

				if inMsg.FromExternalTarget(listenPort) {
					//TODO verify
					// Replying with RST only to external target
					srcPortRange := PortRange{pkt.srcPort, pkt.srcPort}
					seqNum := pkt.ackNum
					ackNum := pkt.seqNum + 1
					err = send(af, srcAddr, &fromAddr, defines.PortHTTPS, srcPortRange,
						DSCPBeLow, rst, seqNum, ackNum, sentC, kill, logger)
					if err != nil {
						logger.Fatal("failed to send RST", zap.Error(err))
					}
				}

			case pkt.hasFlag(rst):
				// Received RST (closed port or reset from other side)
				logger.Warn("Received",
					zap.String("flag", "RST"),
					zap.Object("port", pkt.srcPort))

			}

			select {
			case <-kill:
				logger.Info("TCP receiver terminating...", zap.String("AF", af))
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

// EchoTargets sends echoes (SYNs) to all targets included in 'remotes'
func EchoTargets(
	remotes interface{},
	srcAddr *net.IP,
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
	logger zap.Logger,
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
				echoTargetsWorker(remotes, srcAddr, targetPort, srcPortRange, *currentDSCP,
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
						logger.Debug("Completed echoing and uploading all stats of current "+
							"batch cycle in", zap.String("duration", t1.Sub(t0).String()))
						continue
					}
					t1 := time.Now()
					logger.Debug("Completed echoing current batch cycle in",
						zap.String("duration", t1.Sub(t0).String()))
					continue
				}
			}
		}
	}()
}

func echoTargetsWorker(
	remotes interface{},
	srcAddr *net.IP,
	targetPort uint16,
	srcPortRange PortRange,
	DSCPv DSCPValue,
	realBatchInterval time.Duration,
	batchEndCycle *time.Ticker,
	sentC chan Message,
	kill chan struct{},
	logger zap.Logger,
) error {

	r := reflect.ValueOf(remotes)

	if r.Kind() != reflect.Map {
		return fmt.Errorf("remote interface not a map in echoTargetsWorker()")
	}

	// Echo interval is half the time of the 'real' batch interval
	echoInterval := time.Duration(int(realBatchInterval) / 2 / len(r.MapKeys()))
	tickCh := time.NewTicker(echoInterval).C

	for _, key := range r.MapKeys() {
		remoteStruct := r.MapIndex(key)
		if remoteStruct.Kind() != reflect.Struct {
			return fmt.Errorf("remote field not a struct in tcp.EchoTargets()")
		}
		dstAddr := net.IP(remoteStruct.FieldByName("IP").Bytes())
		ext := remoteStruct.FieldByName("External").Bool()

		// Send SYN with random SEQ
		port := targetPort
		qos := DSCPv
		if ext {
			port = defines.PortHTTPS
			qos = DSCPBeLow
		}
		err := send(remoteStruct.FieldByName("AF").String(), srcAddr, &dstAddr, port, srcPortRange, qos,
			syn, rand.Uint32(), 0, sentC, kill, logger)
		if err != nil {
			return fmt.Errorf("%s", err)
		}

		select {
		case <-tickCh:
			continue
		case <-batchEndCycle.C:
			return nil
		}
	}
	return nil
}

// Sender generates TCP packet probes with given TTL at given packet per second rate
// The packet are injected into raw socket and their descriptions are published to the output channel as Probe messages
//TODO Test IPv6
func send(
	af string,
	srcAddr *net.IP,
	dstAddr *net.IP,
	targetPort uint16,
	srcPortRange PortRange,
	DSCPv DSCPValue,
	ctrlFlags uint8,
	seqNum uint32,
	ackNum uint32,
	sentC chan Message,
	kill chan struct{},
	logger zap.Logger,
) error {
	var (
		err        error
		sendSocket int
	)

	// create the socket
	switch af {
	case "ip4":
		sendSocket, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	case "ip6":
		sendSocket, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	default:
		return fmt.Errorf("unhandled AF family")
	}
	if err != nil {
		return err
	}

	// bind the socket
	switch af {
	case "ip4":
		var sockaddr [4]byte
		copy(sockaddr[:], srcAddr.To4())
		err = syscall.Bind(sendSocket, &syscall.SockaddrInet4{Port: 0, Addr: sockaddr})
	case "ip6":
		var sockaddr [16]byte
		copy(sockaddr[:], srcAddr.To16())
		err = syscall.Bind(sendSocket, &syscall.SockaddrInet6{Port: 0, Addr: sockaddr})
	default:
		return fmt.Errorf("unhandled AF family")
	}
	if err != nil {
		return err
	}

	// set the QoS DSCP on the socket by setting the TOS field value
	switch af {
	case "ip4":
		err = syscall.SetsockoptInt(sendSocket, syscall.IPPROTO_IP, syscall.IP_TOS, int(DSCPv))
	case "ip6":
		err = syscall.SetsockoptInt(sendSocket, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, int(DSCPv))
	}
	if err != nil {
		return err
	}

	go func() {
		defer syscall.Close(sendSocket)

		var flag string

		rand.Seed(time.Now().UnixNano())
		for srcPort := srcPortRange[0]; srcPort <= srcPortRange[1]; srcPort++ {
			packet, err := makePkt(af, srcAddr, dstAddr, srcPort, targetPort, ctrlFlags, seqNum, ackNum)
			if err != nil {
				logger.Error("error creating packet", zap.Error(err))
				break
			}

			switch af {
			case "ip4":
				var sockAddr [4]byte
				copy(sockAddr[:], dstAddr.To4())
				err = syscall.Sendto(sendSocket, packet, 0,
					&syscall.SockaddrInet4{Port: 0, Addr: sockAddr})
			case "ip6":
				var sockAddr [16]byte
				copy(sockAddr[:], dstAddr.To16())
				// with IPv6 the dst port must be zero, otherwise the syscall fails
				err = syscall.Sendto(sendSocket, packet, 0,
					&syscall.SockaddrInet6{Port: 0, Addr: sockAddr})
			default:
				logger.Fatal("unhandled AF family", zap.String("AF", af))
			}
			sendRunTime := monoNow()
			sendUnixTime := timeNow()

			switch {
			case (ctrlFlags&syn != 0) && (ctrlFlags&ack == 0):
				flag = "SYN"

				// Send 'echo' request message to collector
				sentC <- Message{
					Type:    EchoRequest,
					SrcAddr: *srcAddr,
					DstAddr: *dstAddr,
					Af:      af,
					SrcPort: srcPort,
					QosDSCP: DSCPv,
					Ts: Timestamp{
						Run:  sendRunTime,
						Unix: sendUnixTime},
					Seq: seqNum,
					Ack: ackNum,
				}
			case ctrlFlags&syn != 0 && (ctrlFlags&ack != 0):
				flag = "SYN ACK"
			case ctrlFlags&rst != 0:
				flag = "RST"
			default:
				flag = ""
			}

			srcZap := zap.Nest("source",
				zap.String("address", srcAddr.String()),
				zap.Object("port", srcPort))
			dstZap := zap.Nest("destination",
				zap.String("address", dstAddr.String()),
				zap.Object("port", targetPort))
			if err != nil {
				logger.Debug("failed to send out", zap.String("flag", flag), srcZap, dstZap)
				break
			}
			logger.Debug("Sent", zap.String("flag", flag), srcZap, dstZap)

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
