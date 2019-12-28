package client

import (
	"fmt"
	"github.com/cakturk/go-netstat/netstat"
	"github.com/fatedier/frp/models/config"
	"log"
	"net"
	"strconv"
	"strings"
)

var lastUdpOpen []netstat.SockTabEntry = nil
var lastTcpOpen []netstat.SockTabEntry = nil

var lastUdpOpenStr = ""
var lastTcpOpenStr = ""

var BlacklistPort []uint16
var BlacklistProcess []string
var BlacklistIP []string
var BlacklistIPPort []string

func updateForwardBlacklist(cfg config.ClientCommonConf) {
	BlacklistIP = cfg.BlackListIP
	BlacklistPort = cfg.BlackListPort
	BlacklistIPPort = cfg.BlackListIPPort
	BlacklistProcess = cfg.BlackListProcess
}

func notBlacklisted(s *netstat.SockTabEntry) bool {
	if s.State != netstat.Listen {
		return false
	}
	if s.LocalAddr.IP.IsLoopback() {
		return false
	}
	for _, port := range BlacklistPort {
		if s.LocalAddr.Port == port {
			return false
		}
	}
	for _, ipport := range BlacklistIPPort {
		colonIndex := strings.LastIndexByte(ipport, ':')
		ipstr := ipport[:colonIndex]
		ipstr = strings.Replace(ipstr, "[", "", 1)
		ipstr = strings.Replace(ipstr, "]", "", 1)
		port, err := strconv.Atoi(ipport[colonIndex+1:])
		if err != nil {
			fmt.Printf("Invalid ip:port %s\n", ipport)
		}
		if strings.Contains(ipstr, "/") {
			// CIDR
			_, ipnet, err := net.ParseCIDR(ipstr)
			if err != nil || ipnet == nil {
				fmt.Printf("Invalid CIDR: %s\n", ipstr)
				continue
			}
			if ipnet.Contains(s.LocalAddr.IP) && s.LocalAddr.Port == uint16(port) {
				return false
			}
		} else {
			// IP
			ip := net.ParseIP(ipstr)
			if s.LocalAddr.IP.Equal(ip) && s.LocalAddr.Port == uint16(port) {
				return false
			}
		}
	}
	for _, process := range BlacklistProcess {
		if strings.SplitN(s.Process.String(), "/", 2)[1] == process {
			return false
		}
	}
	for _, ipstr := range BlacklistIP {
		if strings.Contains(ipstr, "/") {
			// CIDR
			_, ipnet, err := net.ParseCIDR(ipstr)
			if err != nil || ipnet == nil {
				fmt.Printf("Invalid CIDR: %s\n", ipstr)
				continue
			}
			if ipnet.Contains(s.LocalAddr.IP) {
				return false
			}
		} else {
			// IP
			ip := net.ParseIP(ipstr)
			if s.LocalAddr.IP.Equal(ip) {
				return false
			}
		}
	}
	return true
}

func tabs2Str (tabs *[]netstat.SockTabEntry) string {
	var tabsStr  = ""
	for _, tab := range *tabs {
		tabsStr += fmt.Sprintf("%v\n", tab)
	}
	return tabsStr
}

func refreshNetstat(ForwardProtocol int) bool {
	var changed = false
	var udpOpenStr = ""
	var tcpOpenStr = ""
	// tcp
	if ForwardProtocol & 0x1 != 0 {
		tcpOpen, tcpNetstatError := netstat.TCPSocks(notBlacklisted)
		if tcpNetstatError == nil && lastTcpOpen == nil {
			for _, e := range tcpOpen {
				log.Printf("TCP: %v\n", e)
			}
		}
		if len(tcpOpen) != len(lastTcpOpen) {
			goto tcpchanged
		}
		tcpOpenStr = tabs2Str(&tcpOpen)
		if tcpOpenStr != lastTcpOpenStr {
			goto tcpchanged
		}
		goto tcpunchanged
tcpchanged:
	lastTcpOpen = tcpOpen
	lastTcpOpenStr = tcpOpenStr
	changed = true
tcpunchanged:
	}
	// udp
	if ForwardProtocol & 0x2 != 0 {
		udpOpen, udpNetstatError := netstat.UDPSocks(notBlacklisted)
		if udpNetstatError == nil && lastUdpOpen == nil {
			for _, e := range udpOpen {
				log.Printf("UDP: %v\n", e)
			}
		}
		if len(udpOpen) != len(lastUdpOpen) {
			goto udpchanged
		}
		// not sorting for better performance, in price of fake reporting
		udpOpenStr = tabs2Str(&udpOpen)
		if udpOpenStr != lastUdpOpenStr {
			goto udpchanged
		}
		goto udpunchanged
udpchanged:
	lastUdpOpen = udpOpen
	lastUdpOpenStr = udpOpenStr
	changed = true
udpunchanged:
	}
	return changed
}
