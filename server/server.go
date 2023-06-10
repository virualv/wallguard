package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Host string `yaml:"bind"`
		Port int    `yaml:"port"`
		Ssl  struct {
			CertPath         string `yaml:"cert_path"`
			KeyPath          string `yaml:"key_path"`
			ClientCaCertPath string `yaml:"client_ca_path"`
		} `yaml:"ssl"`
		CacheDir   string   `yaml:"cache_dir"`
		PortRange  string   `yaml:"open_ports"`
		AllowUUIDs []string `yaml:"allow_uuids"`
	} `yaml:"server"`
}

var configPath = flag.String("c", "config.yaml", "config path")
var help = flag.Bool("h", false, "Show help")

func main() {
	var config Config
	var host string
	var port int
	var sslCertPath string
	var sslKeyPath string
	var sslClientCaCertPath string
	var cacheDir string
	var openPortRange string
	var allowUUIDs []string

	flag.Parse()
	// check args
	if *configPath == "" || *help {
		flag.Usage()
		os.Exit(0)
	}
	// parse config file
	data, err := ioutil.ReadFile(*configPath)
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [server]: please check config path. %v\033[0m\n", err)
		return
	}
	// read config item
	host = config.Server.Host
	port = config.Server.Port
	sslCertPath = config.Server.Ssl.CertPath
	sslKeyPath = config.Server.Ssl.KeyPath
	sslClientCaCertPath = config.Server.Ssl.ClientCaCertPath
	cacheDir = config.Server.CacheDir
	openPortRange = config.Server.PortRange
	allowUUIDs = config.Server.AllowUUIDs

	if host == "" || port == 0 || sslCertPath == "" || sslKeyPath == "" || sslClientCaCertPath == "" || cacheDir == "" || openPortRange == "" || len(allowUUIDs) == 0 {
		log.Fatalf("\033[1;31;40mWallGuard [server]: please check config items.\033[0m\n")
		os.Exit(-1)
	}

	service := host + ":" + strconv.Itoa(port)
	tlsConfig := loadSSL(sslCertPath, sslKeyPath, sslClientCaCertPath)

	listener, err := tls.Listen("tcp", service, &tlsConfig)
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
		handleClient(conn, cacheDir, openPortRange, allowUUIDs)
	}
}

// load ssl ceritificate and key
func loadSSL(certPath string, keyPath string, clientCaCertPath string) tls.Config {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [server]: loadkeys: %s\033[0m\n", err)
	}

	clientCaCertBytes, err := ioutil.ReadFile(clientCaCertPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [server]: Unable to read client cert file\033[0m\n")
		os.Exit(-3)
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(clientCaCertBytes)
	if !ok {
		log.Fatalf("\033[1;31;40mWallGuard [server]: failed to parse client certificate\033[0m\n")
		os.Exit(-3)
	}
	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}
	config.Rand = rand.Reader
	return config
}

// handle client request
func handleClient(conn net.Conn, cacheDir string, portRange string, allowUUIDs []string) {
	defer conn.Close()
	buf := make([]byte, 512)
	var ipAddr string
	var uuid string

	log.Print("WallGuard [server]: conn: waiting")
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("\033[1;31;40mWallGuard [server]: conn: read: %s\033[0m\n", err)
		return
	}
	log.Printf("WallGuard [server]: conn: rev data: %q", string(buf[:n]))
	revData := string(buf[:n])
	revData = strings.Replace(revData, " ", "", -1)
	revData = strings.Replace(revData, "\n", "", -1)
	revSlice := strings.Split(revData, ",")
	uuid = revSlice[0]
	ipAddr = revSlice[1]
	for _, allowUUID := range allowUUIDs {
		if allowUUID != uuid {
			log.Printf("\033[1;33;40mWallGuard [server]: {warnning} the uuid [%v] for this client is invalid \033[0m\n", uuid)
			n, err = io.WriteString(conn, "client uuid: "+uuid+" is blocked by server")
			if err != nil {
				log.Printf("WallGuard [server]: failed to send msg: %s", err)
			}
			return
		}
	}
	n, err = conn.Write(buf[:n])
	if err != nil {
		log.Printf("WallGuard [server]: write: %s", err)
		return
	}
	log.Printf("WallGuard [server]: conn: wrote %d bytes", n)
	handleFirewall(ipAddr, cacheDir, uuid, portRange)
	log.Println("WallGuard [server]: conn: closed")
}

// cache client ip info
func cacheIpInfo(ipAddr string, cacheDir string, uuid string) {
	_, err := os.Stat(cacheDir)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(cacheDir, os.ModePerm)
		if err != nil {
			panic(err)
		}
	}

	filePath := cacheDir + "/" + uuid
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		file, err := os.Create(filePath)
		if err != nil {
			log.Fatalf("\033[1;31;40mWallGuard [server]: cann't create file. ERROR: %s\033[0m\n", err)
			os.Exit(-2)
		}
		defer file.Close()
	}

	err = ioutil.WriteFile(filePath, []byte(ipAddr), 0600)
	if err != nil {
		panic(err)
	}
}

// read old client ip info from cache
func readOldIpInfo(cacheDir string, uuid string) string {
	filePath := cacheDir + "/" + uuid
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
func addRule(chain string, ruleSpec []string) {
	ipt, err := iptables.New()
	if err != nil {
		log.Println("\033[1;31;40mWallGuard [firewall]: Failed to new up an iptables intance. ERROR: %s\033[0m\n", err)
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
func deleteRule(chain string, ruleSpec []string) {
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
	e, ok := err.(*iptables.Error)
	if err != nil {
		if ok && e.IsNotExist() {
			log.Printf("\033[1;32;40mWallGuard [firewall]: this is a new firewall rule. \033[0m\n")
			return
		} else {
			log.Printf("\033[1;31;40mWallGuard [firewall]: Failed to delete '%v' from %v . ERROR: %v\033[0m\n", ruleSpec, chain, err)
		}
	}
	log.Printf("\033[1;32;40mWallGuard [firewall]: Congratulations, successfully deleted '%s'  %v rule\033[0m\n", chain, ruleSpec)
}

// handle firewall operation
func handleFirewall(ipAddr string, cacheDir string, uuid string, portRange string) {
	var oldIpAddr string
	oldIpAddr = readOldIpInfo(cacheDir, uuid)
	if oldIpAddr == ipAddr {
		log.Printf("\033[1;36;40mWallGuard [server]: user: %v ip: %v no change\033[0m", uuid, ipAddr)
		return
	} else {
		cacheIpInfo(ipAddr, cacheDir, uuid)
	}

	// clean old rule
	if oldIpAddr != "" {
		deleteTcpRuleSpec := []string{"-s", string(oldIpAddr) + "/32", "-p", "tcp", "-m", "multiport", "--dports", string(portRange), "-j", "ACCEPT"}
		deleteRule("INPUT", deleteTcpRuleSpec)
		deleteUdpRuleSpec := []string{"-s", string(oldIpAddr) + "/32", "-p", "udp", "-m", "multiport", "--dports", string(portRange), "-j", "ACCEPT"}
		deleteRule("INPUT", deleteUdpRuleSpec)
	}

	deleteBanTcpRuleSpec := []string{"-p", "tcp", "-m", "multiport", "--dports", string(portRange), "-j", "DROP"}
	deleteRule("INPUT", deleteBanTcpRuleSpec)
	deleteBanUdpRuleSpec := []string{"-p", "tcp", "-m", "multiport", "--dports", string(portRange), "-j", "DROP"}
	deleteRule("INPUT", deleteBanUdpRuleSpec)

	// add new rule
	addAllowTcpRuleSpec := []string{"-s", string(ipAddr) + "/32", "-p", "tcp", "-m", "multiport", "--dports", string(portRange), "-j", "ACCEPT"}
	addRule("INPUT", addAllowTcpRuleSpec)
	addAllowUdpRuleSpec := []string{"-s", string(ipAddr) + "/32", "-p", "udp", "-m", "multiport", "--dports", string(portRange), "-j", "ACCEPT"}
	addRule("INPUT", addAllowUdpRuleSpec)

	// addAllowLoRuleSpec := []string{"-i", "lo", "-j" ,"ACCEPT"}
	// addRule(ipt, 'INPUT', addAllowLoRuleSpec)
	addBanTcpRuleSpec := []string{"-p", "tcp", "-m", "multiport", "--dports", string(portRange), "-j", "DROP"}
	addRule("INPUT", addBanTcpRuleSpec)
	addBanUdpRuleSpec := []string{"-p", "tcp", "-m", "multiport", "--dports", string(portRange), "-j", "DROP"}
	addRule("INPUT", addBanUdpRuleSpec)
	log.Printf("\033[1;32;40mWallGuard [server]: {FIREWALL_RULE_UPDATE} %v already removed, %v have been added\033[0m\n", oldIpAddr, ipAddr)
}
