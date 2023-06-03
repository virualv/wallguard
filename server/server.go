package main

import (
	"github.com/coreos/go-iptables/iptables"
	"io/ioutil"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"fmt"
	"os"
	"log"
	"net"
	"flag"
)

var bindIp = flag.String("bind", "0.0.0.0", "bind ip")
var bindPort = flag.String("port", "28443", "bind port")
var certPath = flag.String("cert", "", "ssl certificate file path")
var keyPath = flag.String("key", "", "ssl key file path")
var cacheDirPath = flag.String("cache-path", "/tmp/wallguard", "ip cache dir path")
var portRange = flag.String("port-range", "", "whitelist port ranges")
var help = flag.Bool("help", false, "Show help")

func main() {
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// 检查是否提供了必要的参数
	if *certPath == "" || *keyPath == "" || *portRange == "" {
		fmt.Println("WallGuard [server]: please check arguments.")
		flag.Usage()
		os.Exit(0)
	}

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [server]: loadkeys: %s\033[0m\n", err)
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	config.Rand = rand.Reader
	service := *bindIp + ":" + *bindPort
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("WallGuard [server]: listen: %s", err)
		return
	}
	log.Print("WallGuard Server is started")
	log.Print("WallGuard: listening to ", service)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("\033[1;31;40mWallGuard [server]: accept: %s\033[0m\n", err)
			break
		}
		log.Printf("\033[1;34;40mWallGuard [server]: accepted from %s\033[0m\n", conn.RemoteAddr())
		tlscon, ok := conn.(*tls.Conn)
		if ok {
			log.Printf("\033[1;32;40mtls connection is ok\033[0m\n")
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		handleClient(conn, *portRange)
	}
}

func handleClient(conn net.Conn, portRange string) {
	defer conn.Close()
	buf := make([]byte, 512)
	var ipAddr string
	var uuid string

	log.Print("WallGuard [server]: conn: waiting")
	n, err := conn.Read(buf)
	if err != nil {
		if err != nil {
			log.Printf("\033[1;31;40mWallGuard [server]: conn: read: %s\033[0m\n", err)
		}
		return
	}
	log.Printf("WallGuard [server]: conn: rev data: %q", string(buf[:n]))
	n, err = conn.Write(buf[:n])
	revData := string(buf[:n])
	revData = strings.Replace(revData, " ", "", -1)
	revData = strings.Replace(revData, "\n", "", -1)
	revSlice := strings.Split(revData, ",")
	uuid = revSlice[0]
	ipAddr = revSlice[1]
	log.Printf("WallGuard [server]: conn: wrote %d bytes", n)

	if err != nil {
		log.Printf("WallGuard [server]: write: %s", err)
		return
	}
	handleFirewall(ipAddr, uuid, portRange)
	log.Println("WallGuard [server]: conn: closed")
}

func cacheIpInfo(ipAddr string, uuid string) {
	_,err := os.Stat(*cacheDirPath)
    if err != nil && os.IsNotExist(err) {
		err=os.MkdirAll(*cacheDirPath, os.ModePerm)
		if err != nil {
			panic(err)
		}
    }
	filePath := *cacheDirPath
	filePath = filePath + "/"  + uuid
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		file, err := os.Create(filePath)
		if err != nil {
			log.Fatalf("\033[1;31;40mWallGuard [server]: cann't create file. ERROR: %s\033[0m\n", err)
			os.Exit(-2)
		}
		defer file.Close()
	}

	err = ioutil.WriteFile(filePath, []byte(ipAddr), 0644)
	if err != nil {
        panic(err)
    }
}

func readOldIpInfo(uuid string) string {
	filePath := *cacheDirPath + "/"  + uuid
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("\033[1;34;40mWallGuard [server]: {%s} is a new client. \033[0m\n", uuid)
		return ""
	}
	oldIpAddr, err := ioutil.ReadFile(filePath)
	if err != nil {
	   panic(err)
	}
	return string(oldIpAddr)
}


// add rule
func addRule(chain string, ruleSpec []string)  {
	ipt, err := iptables.New()
	if err != nil {
		log.Println("\033[1;31;40mWallGuard [firewall]: Failed to new up an IPtables intance. ERROR: %s\033[0m\n", err)
		return
	}
	if _, err = ipt.List("filter", chain); err != nil {
		log.Println("\033[1;31;40mWallGuard [firewall]: Could not use iptables, continuing without - %s\033[0m\n", err)
		ipt = nil
	}
	err = ipt.AppendUnique("filter", chain, ruleSpec...)
	if err != nil {
		log.Println("\033[1;31;40mWallGuard [firewall]: Failed add '%s' to %s. ERROR: %s\033[0m\n", ruleSpec, chain, err)
		return
	}
	log.Printf("\033[1;32;40mWallGuard [firewall]: Congratulations, successfully added '%s' to %v rule\033[0m\n", chain, ruleSpec)
}

// delete rule
func deleteRule(chain string, ruleSpec []string)  {
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("\033[1;31;40mWallGuard [firewall]: Failed to new up an IPtables intance. ERROR: %v\033[0m\n", err)
		return
	}
	if _, err = ipt.List("filter", chain); err != nil {
		log.Printf("\033[1;31;40mWallGuard [firewall]: Could not use iptables, continuing without - %v\033[0m\n", err)
		ipt = nil
	}
	err = ipt.DeleteIfExists("filter", chain, ruleSpec...)
	if err != nil {
		log.Printf("\033[1;31;40mWallGuard [firewall]: Failed to delete '%v' from %v . ERROR: %v\033[0m\n", ruleSpec, chain, err)
		return
	}
	log.Printf("\033[1;32;40mWallGuard [firewall]: Congratulations, successfully deleted '%s'  %v rule\033[0m\n", chain, ruleSpec)
}

func handleFirewall(ipAddr string, uuid string, portRange string) {
	var oldIpAddr string
	oldIpAddr = readOldIpInfo(uuid)
	if oldIpAddr == ipAddr {
		log.Printf("\033[1;36;40mWallGuard [server]: user{%v} 's ip(%v) no change\033[0m", uuid, ipAddr)
		return
	} else {
		cacheIpInfo(ipAddr, uuid)
	}
	
	// clean old rule
	deleteTcpRuleSpec := []string{"-s", string(oldIpAddr) + "/32", "-p", "tcp", "-m", "multiport","--dports", string(portRange), "-j", "ACCEPT"}
	deleteRule("INPUT", deleteTcpRuleSpec)
	deleteUdpRuleSpec := []string{"-s", string(oldIpAddr) + "/32", "-p", "udp", "-m", "multiport","--dports", string(portRange), "-j", "ACCEPT"}
	deleteRule("INPUT", deleteUdpRuleSpec)

	deleteBanTcpRuleSpec := []string{"-p", "tcp", "-m", "multiport","--dports", string(portRange), "-j", "DROP"}
	deleteRule("INPUT", deleteBanTcpRuleSpec)
	deleteBanUdpRuleSpec := []string{"-p", "tcp", "-m", "multiport","--dports", string(portRange), "-j", "DROP"}
	deleteRule("INPUT", deleteBanUdpRuleSpec)

	// add new rule
	addAllowTcpRuleSpec := []string{"-s", string(ipAddr) + "/32", "-p", "tcp", "-m", "multiport","--dports", string(portRange), "-j", "ACCEPT"}
	addRule("INPUT", addAllowTcpRuleSpec)
	addAllowUdpRuleSpec := []string{"-s", string(ipAddr) + "/32", "-p", "udp", "-m", "multiport","--dports", string(portRange), "-j", "ACCEPT"}
	addRule("INPUT", addAllowUdpRuleSpec)

	// addAllowLoRuleSpec := []string{"-i", "lo", "-j" ,"ACCEPT"}
	// addRule(ipt, 'INPUT', addAllowLoRuleSpec)
	addBanTcpRuleSpec := []string{"-p", "tcp", "-m", "multiport","--dports", string(portRange), "-j", "DROP"}
	addRule("INPUT", addBanTcpRuleSpec)
	addBanUdpRuleSpec := []string{"-p", "tcp", "-m", "multiport","--dports", string(portRange), "-j", "DROP"}
	addRule("INPUT", addBanUdpRuleSpec)
	log.Printf("\033[1;32;40mWallGuard [server]: {FIREWALL_RULE_UPDATE} %v already removed, %v have been added\033[0m\n", oldIpAddr, ipAddr)
}