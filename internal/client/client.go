package client

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"wallguard/internal/config"
)

// Run 启动客户端
func Run(cfg *config.ClientConfig) {
	// 检查 SNI 配置
	if cfg.SSL.SNI == "" {
		log.Printf("\033[1;34;40mWallGuard [client]: warning: SNI not set in config.\033[0m\n")
	}

	var sleepInterval time.Duration

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient := &http.Client{Transport: tr}

	cert, err := tls.LoadX509KeyPair(cfg.SSL.CertPath, cfg.SSL.KeyPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: loadkeys: %s\033[0m\n", err)
	}

	sleepInterval, err = time.ParseDuration(cfg.Interval)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: parse interval error: %v\033[0m\n", err)
	}

	certBytes, err := os.ReadFile(cfg.SSL.CertPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: unable to read cert file: %v\033[0m\n", err)
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		log.Fatalf("\033[1;31;40mWallGuard [client]: failed to parse root certificate\033[0m\n")
	}

	tlsConfig := tls.Config{
		RootCAs:            clientCertPool,
		Certificates:       []tls.Certificate{cert},
		ServerName:         cfg.SSL.SNI,
		InsecureSkipVerify: cfg.SSL.SkipVerify,
	}

	serverURI := cfg.ServerIP + ":" + cfg.ServerPort
	log.Printf("\033[1;34;40mWallGuard [client]: uuid: %v\033[0m\n", cfg.UUID)

	for {
		log.Println("WallGuard [client]: Query my public ip address")
		ipAddr := queryLocalIp(httpClient, cfg.CheckIPURL)
		if ipAddr == "" {
			log.Fatalf("\033[1;31;40mWallGuard [client]: query public ip fail, please check 'check_ip_url' in config file\033[0m\n")
		}
		sdata := cfg.UUID + "," + ipAddr
		log.Printf("\033[1;34;40mWallGuard [client]: my current public ip addr is %v\033[0m\n", ipAddr)
		sendData(&tlsConfig, serverURI, sdata)
		log.Printf("\033[1;34;40mWallGuard [client]: time sleep %v\033[0m\n", cfg.Interval)
		time.Sleep(sleepInterval)
	}
}

func queryLocalIp(client *http.Client, checkIpUrl string) string {
	resp, err := client.Get(checkIpUrl)

	if err != nil {
		log.Printf("\033[1;31;40mWallGuard [client]: [queryPublicIP] error: %v\033[0m\n", err)
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("\033[1;31;40mWallGuard [client]: [queryPublicIP] error: %v\033[0m\n", err)
		return ""
	}
	queryData := string(body)
	queryData = strings.Replace(queryData, " ", "", -1)
	queryData = strings.Replace(queryData, "\n", "", -1)
	return queryData
}

func sendData(tlsConfig *tls.Config, serverURI string, data string) {
	conn, err := tls.Dial("tcp", serverURI, tlsConfig)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: dial: %s\033[0m\n", err)
	}
	defer conn.Close()
	log.Printf("\033[1;32;40mWallGuard [client]: connected to: %v\033[0m\n", conn.RemoteAddr())

	state := conn.ConnectionState()
	log.Printf("\033[1;32;40mWallGuard [client]: handshake: %v\033[0m\n", state.HandshakeComplete)
	log.Printf("\033[1;32;40mWallGuard [client]: protocol version: %v\033[0m\n", state.Version)

	_, err = io.WriteString(conn, data)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: write: %s\033[0m\n", err)
	}
	reply := make([]byte, 256)
	n, err := conn.Read(reply)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: read: %s\033[0m\n", err)
	}
	if n == 0 {
		log.Fatalf("\033[1;31;40mWallGuard [client]: send failed\033[0m\n")
		return
	}
	revData := string(reply[:n])
	if strings.Contains(revData, "World") {
		log.Printf("\033[1;31;40mWallGuard [client]: %q (%d bytes)\033[0m\n", string(reply[:n]), n)
	} else {
		log.Printf("\033[1;34;40mWallGuard [client]: read %q (%d bytes)\033[0m\n", string(reply[:n]), n)
	}
}
