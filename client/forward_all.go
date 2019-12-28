package client

import (
	"fmt"
	"github.com/cakturk/go-netstat/netstat"
	"github.com/fatedier/frp/models/config"
	"github.com/fatedier/frp/utils/log"
	"github.com/vaughan0/go-ini"
	"net"
	"strconv"
	"strings"
	"time"
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
	for _, port := range BlacklistPort {
		if s.LocalAddr.Port == port {
			return false
		}
	}
	for _, ipport := range BlacklistIPPort {
		colonIndex := strings.LastIndexByte(ipport, ':')
		ipstr := ipport[:colonIndex]
		ipstr = strings.Replace(ipstr, "[", "", -1)
		ipstr = strings.Replace(ipstr, "]", "", -1)
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
		ipstr = strings.Replace(ipstr, "[", "", -1)
		ipstr = strings.Replace(ipstr, "]", "", -1)
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

func tabs2Str(tabs *[]netstat.SockTabEntry) string {
	var tabsStr = ""
	for _, tab := range *tabs {
		tabsStr += fmt.Sprintf("%v\n", tab)
	}
	return tabsStr
}

func refreshNetstat(ForwardProtocol string) bool {
	var changed = false
	var udpOpenStr = ""
	var tcpOpenStr = ""
	// tcp
	if strings.Contains(ForwardProtocol, "tcp") || ForwardProtocol == "true" {
		tcpOpen, tcpNetstatError := netstat.TCPSocks(notBlacklisted)
		if tcpNetstatError == nil && lastTcpOpen == nil {
			for _, e := range tcpOpen {
				log.Info("TCP: %v", e)
			}
		}
		if len(tcpOpen) != len(lastTcpOpen) {
			goto tcpchanged
		}
		// not sorting for better performance, in price of fake reporting
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
	if strings.Contains(ForwardProtocol, "udp") || ForwardProtocol == "true" {
		udpOpen, udpNetstatError := netstat.UDPSocks(notBlacklisted)
		if udpNetstatError == nil && lastUdpOpen == nil {
			for _, e := range udpOpen {
				log.Info("UDP: %v", e)
			}
		}
		if len(udpOpen) != len(lastUdpOpen) {
			goto udpchanged
		}
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

func ForwardAllDaemon(svr *Service) {
	if svr == nil {
		return
	}

	for {
		if !refreshNetstat(svr.cfg.ForwardAll) {
			time.Sleep(time.Duration(svr.cfg.ForwardAllRefreshInterval) * time.Second)
			continue
		}

		content, err := config.GetRenderedConfFromFile(svr.cfgFile)
		if err != nil {
			log.Warn("reload frpc config file error: %v", err)
			continue
		}

		newCommonCfg, err := config.UnmarshalClientConfFromIni(content)
		if err != nil {
			log.Warn("reload frpc common section error: %v", err)
			continue
		}

		pxyCfgs, visitorCfgs, err := config.LoadAllConfFromIni(svr.cfg.User, content, newCommonCfg.Start)
		if err != nil {
			log.Warn("reload frpc proxy config error: %v", err)
			continue
		}

		var newPxyCfgs = map[string]config.ProxyConf{}
		for name, conf := range pxyCfgs {
			newPxyCfgs[name] = conf
		}

		for i, tcpPort := range lastTcpOpen {
			var prefix string
			var name = fmt.Sprintf("_forward_all_tcp_%d_%s", i, tcpPort.Process.String())
			var section = ini.Section{
				"type":            "tcp",
				"local_ip":        tcpPort.LocalAddr.IP.String(),
				"local_port":      strconv.FormatInt(int64(tcpPort.LocalAddr.Port), 10),
				"remote_port":     strconv.FormatInt(int64(tcpPort.LocalAddr.Port), 10),
				"use_encryption":  strconv.FormatBool(svr.cfg.AllUseEncryption),
				"use_compression": strconv.FormatBool(svr.cfg.AllUseCompression),
			}
			proxyCfg, err := config.NewProxyConfFromIni(prefix, name, section)
			if err != nil {
				log.Warn("Failed to add dynamic proxy to forward all tcp (%v): %v\n", err, tcpPort)
				continue
			}
			newPxyCfgs[name] = proxyCfg
		}

		for i, udpPort := range lastUdpOpen {
			var prefix = svr.cfg.User
			if prefix != "" {
				prefix += "."
			}
			var name = fmt.Sprintf("forward_all_udp_%d_%s", i, udpPort.Process.String())
			var section = ini.Section{
				"type":            "udp",
				"local_ip":        udpPort.LocalAddr.IP.String(),
				"local_port":      strconv.FormatInt(int64(udpPort.LocalAddr.Port), 10),
				"remote_port":     strconv.FormatInt(int64(udpPort.LocalAddr.Port), 10),
				"use_encryption":  strconv.FormatBool(svr.cfg.AllUseEncryption),
				"use_compression": strconv.FormatBool(svr.cfg.AllUseCompression),
			}
			proxyCfg, err := config.NewProxyConfFromIni(prefix, name, section)
			if err != nil {
				log.Warn("Failed to add dynamic proxy to forward all tcp (%v): %v\n", err, udpPort)
				continue
			}
			newPxyCfgs[name] = proxyCfg
		}

		err = svr.ReloadConf(newPxyCfgs, visitorCfgs)
		if err != nil {
			fmt.Printf("Failed to reload on port changed: %v\n", err)
		}
	}
}
