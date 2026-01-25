package server

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"wallguard/internal/config"
)

// Run 启动服务端
func Run(cfg *config.ServerConfig) {
	// Initialize firewall manager
	var firewallManager FirewallManager
	firewallBackend := cfg.Firewall.Backend

	if firewallBackend == "" || firewallBackend == "auto" {
		backend := AutoDetectFirewallBackend()
		if backend == "" {
			log.Fatalf("\033[1;31;40mWallGuard [server]: No firewall backend available\033[0m\n")
		}
		var err error
		firewallManager, err = NewFirewallManager(backend)
		if err != nil {
			log.Fatalf("\033[1;31;40mWallGuard [server]: Failed to initialize firewall manager: %v\033[0m\n", err)
		}
	} else {
		var err error
		firewallManager, err = NewFirewallManager(FirewallBackend(firewallBackend))
		if err != nil {
			log.Fatalf("\033[1;31;40mWallGuard [server]: Failed to initialize firewall manager: %v\033[0m\n", err)
		}
	}
	log.Printf("\033[1;32;40mWallGuard [server]: Using firewall backend: %s\033[0m\n", firewallManager.GetBackend())

	service := cfg.Bind + ":" + strconv.Itoa(cfg.Port)
	tlsConfig := loadSSL(cfg.SSL.CertPath, cfg.SSL.KeyPath, cfg.SSL.ClientCAPath)

	listener, err := tls.Listen("tcp", service, tlsConfig)
	if err != nil {
		log.Fatalf("WallGuard [server]: listen: %s", err)
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
		go handleClient(conn, cfg.CacheDir, cfg.OpenPorts, cfg.AllowUUIDs, firewallManager)
	}
}

// load ssl ceritificate and key
func loadSSL(certPath string, keyPath string, clientCaCertPath string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [server]: loadkeys: %s\033[0m\n", err)
	}

	clientCaCertBytes, err := os.ReadFile(clientCaCertPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [server]: Unable to read client cert file\033[0m\n")
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(clientCaCertBytes)
	if !ok {
		log.Fatalf("\033[1;31;40mWallGuard [server]: failed to parse client certificate\033[0m\n")
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
		Rand:         rand.Reader,
	}
	return tlsConfig
}

// handle client request
func handleClient(conn net.Conn, cacheDir string, portRange string, allowUUIDs []string, firewallManager FirewallManager) {
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

	uuidValid := false
	for _, allowUUID := range allowUUIDs {
		if allowUUID == uuid {
			uuidValid = true
			break
		}
	}

	if !uuidValid {
		log.Printf("\033[1;33;40mWallGuard [server]: {warnning} the uuid [%v] for this client is invalid \033[0m\n", uuid)
		_, err = io.WriteString(conn, "client uuid: "+uuid+" is blocked by server")
		if err != nil {
			log.Printf("WallGuard [server]: failed to send msg: %s", err)
		}
		return
	}

	_, err = conn.Write(buf[:n])
	if err != nil {
		log.Printf("WallGuard [server]: write: %s", err)
		return
	}
	log.Printf("WallGuard [server]: conn: wrote %d bytes", n)
	handleFirewall(ipAddr, cacheDir, uuid, portRange, firewallManager)
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
		}
		defer file.Close()
	}

	err = os.WriteFile(filePath, []byte(ipAddr), 0600)
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
	oldIpAddr, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}
	return string(oldIpAddr)
}

// handle firewall operation
func handleFirewall(ipAddr string, cacheDir string, uuid string, portRange string, firewallManager FirewallManager) {
	oldIpAddr := readOldIpInfo(cacheDir, uuid)
	if oldIpAddr == ipAddr {
		log.Printf("\033[1;36;40mWallGuard [server]: user: %v ip: %v no change\033[0m", uuid, ipAddr)
		return
	} else {
		cacheIpInfo(ipAddr, cacheDir, uuid)
	}

	// clean old rules
	if oldIpAddr != "" {
		// Delete old TCP allow rule
		oldTcpRule := FirewallRule{
			SourceIP: oldIpAddr,
			Protocol: "tcp",
			Ports:    portRange,
			Action:   "ACCEPT",
		}
		if err := firewallManager.DeleteRule(oldTcpRule); err != nil {
			log.Printf("\033[1;33;40mWallGuard [server]: Warning: failed to delete old TCP rule: %v\033[0m\n", err)
		}

		// Delete old UDP allow rule
		oldUdpRule := FirewallRule{
			SourceIP: oldIpAddr,
			Protocol: "udp",
			Ports:    portRange,
			Action:   "ACCEPT",
		}
		if err := firewallManager.DeleteRule(oldUdpRule); err != nil {
			log.Printf("\033[1;33;40mWallGuard [server]: Warning: failed to delete old UDP rule: %v\033[0m\n", err)
		}
	}

	// Delete existing ban rules (these are global, not IP-specific)
	// Note: For firewalld and UFW, we don't need to manage global ban rules
	// as they handle this differently than iptables
	if firewallManager.GetBackend() == BackendIptables {
		// For iptables, we need to manage global ban rules
		banTcpRule := FirewallRule{
			SourceIP: "", // Global rule
			Protocol: "tcp",
			Ports:    portRange,
			Action:   "DROP",
		}
		if err := firewallManager.DeleteRule(banTcpRule); err != nil {
			log.Printf("\033[1;33;40mWallGuard [server]: Warning: failed to delete ban TCP rule: %v\033[0m\n", err)
		}

		banUdpRule := FirewallRule{
			SourceIP: "", // Global rule
			Protocol: "udp",
			Ports:    portRange,
			Action:   "DROP",
		}
		if err := firewallManager.DeleteRule(banUdpRule); err != nil {
			log.Printf("\033[1;33;40mWallGuard [server]: Warning: failed to delete ban UDP rule: %v\033[0m\n", err)
		}
	}

	// add new allow rules
	newTcpRule := FirewallRule{
		SourceIP: ipAddr,
		Protocol: "tcp",
		Ports:    portRange,
		Action:   "ACCEPT",
	}
	if err := firewallManager.AddRule(newTcpRule); err != nil {
		log.Printf("\033[1;31;40mWallGuard [server]: Failed to add TCP allow rule: %v\033[0m\n", err)
	}

	newUdpRule := FirewallRule{
		SourceIP: ipAddr,
		Protocol: "udp",
		Ports:    portRange,
		Action:   "ACCEPT",
	}
	if err := firewallManager.AddRule(newUdpRule); err != nil {
		log.Printf("\033[1;31;40mWallGuard [server]: Failed to add UDP allow rule: %v\033[0m\n", err)
	}

	// add ban rules (only for iptables)
	if firewallManager.GetBackend() == BackendIptables {
		banTcpRule := FirewallRule{
			SourceIP: "", // Global rule
			Protocol: "tcp",
			Ports:    portRange,
			Action:   "DROP",
		}
		if err := firewallManager.AddRule(banTcpRule); err != nil {
			log.Printf("\033[1;31;40mWallGuard [server]: Failed to add ban TCP rule: %v\033[0m\n", err)
		}

		banUdpRule := FirewallRule{
			SourceIP: "", // Global rule
			Protocol: "udp",
			Ports:    portRange,
			Action:   "DROP",
		}
		if err := firewallManager.AddRule(banUdpRule); err != nil {
			log.Printf("\033[1;31;40mWallGuard [server]: Failed to add ban UDP rule: %v\033[0m\n", err)
		}
	}

	log.Printf("\033[1;32;40mWallGuard [server]: {FIREWALL_RULE_UPDATE} %v already removed, %v have been added\033[0m\n", oldIpAddr, ipAddr)
}
