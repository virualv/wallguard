package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var serverIp = flag.String("ip", "0.0.0.0", "server ip")
var serverPort = flag.String("port", "2096", "server port")
var sni = flag.String("sni", "", "server port")
var skipVerify = flag.Bool("skip-verify", false, "skip server cert verify")
var certPath = flag.String("cert", "", "ssl certificate file path")
var keyPath = flag.String("key", "", "ssl key file path")
var uuid = flag.String("uuid", "b4e00216-3ac3-4410-97a1-534858bedda8", "identity uuid")
var checkIpUrl = flag.String("check-ip-url", "https://icanhazip.com/", "ssl key file path")
var intervalTime = flag.String("interval", "180s", "update interval time, unit: \"ns\", \"us\" (or \"µs\"), \"ms\", \"s\", \"m\", \"h\"")
var help = flag.Bool("help", false, "Show help")

var config tls.Config
var serverURI string

func main() {
	flag.Parse()
	var sleepInterval time.Duration

	// 检查是否提供了必要的参数
	if *certPath == "" || *keyPath == "" || *uuid == "" {
		log.Printf("\033[1;31;40mWallGuard [client]: please check arguments.\033[0m\n")
		flag.Usage()
		os.Exit(0)
	}

	if *sni == "" {
		log.Printf("\033[1;34;40mWallGuard [warning]: not set sni.\033[0m\n")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: loadkeys: %s\033[0m\n", err)
	}
	sleepInterval, err = time.ParseDuration(*intervalTime)
	if err != nil {
		panic("\033[1;31;40mWallGuard [client]: parse interval error\033[0m\n")
	}
	certBytes, err := ioutil.ReadFile(*certPath)
	if err != nil {
		panic("Unable to read cert.pem")
	}
	clientCertPool := x509.NewCertPool()
	ok := clientCertPool.AppendCertsFromPEM(certBytes)
	if !ok {
		panic("failed to parse root certificate")
	}

	config = tls.Config{
		RootCAs:            clientCertPool,
		Certificates:       []tls.Certificate{cert},
		ServerName:         *sni,
		InsecureSkipVerify: *skipVerify,
	}
	serverURI = *serverIp + ":" + *serverPort
	log.Printf("\033[1;34;40mWallGuard [client]: uuid: %v\033[0m\n", *uuid)
	for {
		log.Println("WallGuard [client]: Query my public ip address")
		ipAddr := queryLocalIp(client)
		if ipAddr == "" {
			log.Fatalf("\033[1;31;40mWallGuard [client]: query public ip fail, please check '-check-ip-url' argument\033[0m\n")
			os.Exit(-1)
		}
		sdata := *uuid + "," + ipAddr
		log.Printf("\033[1;34;40mWallGuard [client]: my current public ip addr is %v\033[0m\n", ipAddr)
		sendData(config, serverURI, sdata)
		log.Printf("\033[1;34;40mWallGuard [client]: time sleep %v\033[0m\n", *intervalTime)
		time.Sleep(sleepInterval)
	}

}

func queryLocalIp(client *http.Client) string {
	resp, err := client.Get(*checkIpUrl)

	if err != nil {
		log.Printf("\033[1;31;40mWallGuard [client]: [queryPublicIP] error: %v\033[0m\n", err)
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("\033[1;31;40mWallGuard [client]: [queryPublicIP] error: %v\033[0m\n", err)
		return ""
	}
	queryData := string(body)
	queryData = strings.Replace(queryData, " ", "", -1)
	queryData = strings.Replace(queryData, "\n", "", -1)
	return queryData
}

func sendData(tlsConfig tls.Config, serverURI string, data string) {
	conn, err := tls.Dial("tcp", serverURI, &tlsConfig)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: dial: %s\033[0m\n", err)
	}
	defer conn.Close()
	log.Printf("\033[1;32;40mWallGuard [client]: connected to: %v\033[0m\n", conn.RemoteAddr())

	state := conn.ConnectionState()
	log.Printf("\033[1;32;40mWallGuard [client]: handshake: %v\033[0m\n", state.HandshakeComplete)
	log.Printf("\033[1;32;40mWallGuard [client]: mutual: %v\033[0m\n", state.NegotiatedProtocolIsMutual)

	n, err := io.WriteString(conn, data)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: write: %s\033[0m\n", err)
	}
	reply := make([]byte, 256)
	n, err = conn.Read(reply)
	if err != nil {
		log.Fatalf("\033[1;31;40mWallGuard [client]: read: %s\033[0m\n", err)
	}
	if n == 0 {
		log.Fatalf("\033[1;31;40mWallGuard [client]: send failed: %s\033[0m\n")
		return
	}
	if strings.Contains(revData, "World") {
		log.Printf("\033[1;31;40mWallGuard [client]: %q \033[0m\n", string(reply[:n]), n)
	} else {
		log.Printf("\033[1;34;40mWallGuard [client]: read %q (%d bytes)\033[0m\n", string(reply[:n]), n)
	}
}
