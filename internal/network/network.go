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

package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/uber-go/zap"
)

// Family returns the string equivalent of the address family provided.
func Family(a *net.IP) string {
	if a == nil || len(*a) <= net.IPv4len {
		return "ip4"
	}
	if a.To4() != nil {
		return "ip4"
	}
	return "ip6"
}

// GetSourceAddr discovers the source address.
func GetSourceAddr(
	af string,
	srcAddr string,
	hostname string,
	ifaceName string,
	logger zap.Logger,
) (*net.IP, error) {

	//TODO => resolve if both interface name and source address are specified and they do not match

	// Source address is specified
	if srcAddr != "" {
		return resolveHost(af, hostname, logger)
	}
	// Interface name is specified
	if ifaceName != "" {
		return interfaceAddress(af, ifaceName)
	}

	return anyInterfaceAddress(af)
}

// Resolve given domain hostname/address in the given address family
//TODO replace with net.LookupHost?
func resolveHost(af string, target string, logger zap.Logger) (*net.IP, error) {
	addr, err := net.ResolveIPAddr(af, target)
	if err != nil {
		logger.Warn("failed net.ResolveIPAddr for target",
			zap.String("target", target),
			zap.Error(err))
		return nil, err
	}

	return &addr.IP, nil
}

// ResolveAddr returns DNS name of given IP address. Returns the same input string, if resolution fails.
func ResolveAddr(target string, servers []net.IP, logger zap.Logger) (string, error) {

	names, err := net.LookupAddr(target)
	if err != nil {
		logger.Warn("failed to DNS resolve target with default server",
			zap.String("target", target),
			zap.Error(err))
		return resolveAddrWServer(target, servers, logger)
	}
	if len(names) == 0 {
		return resolveAddrWServer(target, servers, logger)
	}
	return strings.Replace(names[0], ".prod.uber.internal.", "", -1), nil
}

func resolveAddrWServer(target string, servers []net.IP, logger zap.Logger) (string, error) {

	if servers == nil {
		return "", fmt.Errorf("no alternate DNS servers configured")
	}

	c := dns.Client{}
	m := dns.Msg{}

	fqdn, err := dns.ReverseAddr(target)
	if err != nil {
		return "", err
	}
	m.SetQuestion(fqdn, dns.TypePTR)
	for _, s := range servers {
		r, t, err := c.Exchange(&m, s.String()+":53")
		if err != nil {
			continue
		}
		if len(r.Answer) == 0 {
			err = fmt.Errorf("reverse DNS resolution with own server returned no results")
			continue
		}
		logger.Debug("Reverse DNS resolution for target with user-configured DNS server took",
			zap.String("target", target),
			zap.Float64("duration", t.Seconds()))

		resolved := strings.Split(r.Answer[0].String(), "\t")

		// return fourth tab-delimited field of DNS query response
		return strings.Replace(resolved[4], ".prod.uber.internal.", "", -1), nil
	}
	logger.Warn("failed to DNS resolve target with alternate servers",
		zap.String("target", target))
	return "", fmt.Errorf("failed to DNS resolve %s with alternate servers", target)
}

func interfaceAddress(af string, name string) (*net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("net.InterfaceByName for %s: %s", name, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("iface.Addrs: %s", err)
	}

	return findAddrInRange(af, addrs)
}

func anyInterfaceAddress(af string) (*net.IP, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces: %s", err)
	}

	for _, iface := range interfaces {
		// Skip loopback
		if (iface.Flags & net.FlagLoopback) == net.FlagLoopback {
			continue
		}
		addrs, err := iface.Addrs()
		// Skip if error getting addresses
		if err != nil {
			return nil, fmt.Errorf("error getting addresses for interface %s: %s", iface.Name, err)
		}

		if len(addrs) > 0 {
			return interfaceAddress(af, iface.Name)
		}
	}

	return nil, err
}

func findAddrInRange(af string, addrs []net.Addr) (*net.IP, error) {
	for _, a := range addrs {

		ipnet, ok := a.(*net.IPNet)
		if ok && !(ipnet.IP.IsLoopback() || ipnet.IP.IsMulticast() || ipnet.IP.IsLinkLocalUnicast()) {
			if (ipnet.IP.To4() != nil && af == "ip4") || (ipnet.IP.To4() == nil && af == "ip6") {
				return &ipnet.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("could not find a source address in %s address family", af)
}
