package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/ini.v1"
)

type Config struct {
	Mode         string
	ServerHost   string
	ServerPort   string
	SSHUser      string
	SSHPassword  string
	SNIHost      string
	ListenPort   string
	Payload      string
	WebsocketURL string
	ProxyHost    string // Tambahan untuk tlsmod
	ProxyPort    string // Tambahan untuk tlsmod
	Debug        bool
}

var reconnectMutex sync.Mutex

func loadConfig() (*Config, error) {
	cfg, err := ini.Load("config.ini")
	if err != nil {
		return nil, err
	}

	payload := cfg.Section("payload").Key("custom_payload").String()
	payload = strings.ReplaceAll(payload, "[crlf]", "\r\n")
	payload = strings.ReplaceAll(payload, "[lf]", "\n")
	payload = strings.ReplaceAll(payload, "[cr]", "\r")

	return &Config{
		Mode:         cfg.Section("common").Key("mode").MustString("tls"),
		ServerHost:   cfg.Section("server").Key("host").String(),
		ServerPort:   cfg.Section("server").Key("port").String(),
		SSHUser:      cfg.Section("ssh").Key("user").String(),
		SSHPassword:  cfg.Section("ssh").Key("password").String(),
		SNIHost:      cfg.Section("tls").Key("sni").String(),
		ListenPort:   cfg.Section("local").Key("listen_port").MustString("8989"),
		Payload:      payload,
		WebsocketURL: cfg.Section("websocket").Key("url").String(),
		ProxyHost:    cfg.Section("tlsmod").Key("proxy").String(),
		ProxyPort:    cfg.Section("tlsmod").Key("port").String(),
		Debug:        cfg.Section("common").Key("debug").MustBool(false),
	}, nil
}

func buildPayload(raw, host, port string) string {
	replacer := strings.NewReplacer(
		"[host]", host,
		"[port]", port,
		"[protocol]", "HTTP/1.1",
		"[ua]", "Mozilla/5.0",
	)
	return replacer.Replace(raw)
}

func validateResponse(resp string) bool {
	validCodes := []string{"200", "101"}
	for _, code := range validCodes {
		if strings.Contains(resp, code) {
			return true
		}
	}
	return false
}

func sendSplitPayload(conn net.Conn, payload string) error {
	parts := strings.Split(payload, "[split]")
	for _, p := range parts {
		_, err := conn.Write([]byte(p))
		if err != nil {
			return err
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil
}

func dialTLS(cfg *Config, host, port string) (net.Conn, error) {
	remote := fmt.Sprintf("%s:%s", host, port)
	tlsConfig := &tls.Config{
		ServerName:         cfg.SNIHost,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	return tls.DialWithDialer(dialer, "tcp", remote, tlsConfig)
}

func websocketTunnel(cfg *Config) (net.Conn, error) {
	header := http.Header{}
	header.Set("User-Agent", "Mozilla/5.0")
	header.Set("Upgrade", "websocket")
	header.Set("Connection", "Upgrade")

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			ServerName:         cfg.SNIHost,
			InsecureSkipVerify: true,
		},
		HandshakeTimeout: 10 * time.Second,
	}

	ws, _, err := dialer.Dial(cfg.WebsocketURL, header)
	if err != nil {
		return nil, err
	}
	return ws.UnderlyingConn(), nil
}

func pipe(dst net.Conn, src net.Conn, tag string) {
	defer dst.Close()
	defer src.Close()

	written, err := io.Copy(dst, src)
	if err != nil {
		log.Printf("[-] %s closed: %v", tag, err)
	} else {
		log.Printf("[+] %s transferred %d bytes", tag, written)
	}
}

func handleClient(client net.Conn, cfg *Config) {
	clientAddr := client.RemoteAddr().String()
	log.Printf("[+] Client connected -> %s", clientAddr)

	var remote net.Conn
	var err error

	// Menentukan koneksi dasar berdasarkan Mode
	if cfg.Mode == "ws" {
		log.Printf("[*] Connecting WS -> %s", cfg.WebsocketURL)
		remote, err = websocketTunnel(cfg)
	} else if cfg.Mode == "tlsmod" {
		// Jika tlsmod, koneksi TLS diarahkan ke Proxy Host terlebih dahulu
		log.Printf("[*] Connecting TLSMod via Proxy -> %s:%s", cfg.ProxyHost, cfg.ProxyPort)
		remote, err = dialTLS(cfg, cfg.ProxyHost, cfg.ProxyPort)
	} else {
		log.Printf("[*] Connecting TLS -> %s:%s", cfg.ServerHost, cfg.ServerPort)
		remote, err = dialTLS(cfg, cfg.ServerHost, cfg.ServerPort)
	}

	if err != nil {
		log.Printf("[-] Tunnel gagal: %v", err)
		client.Close()
		return
	}

	log.Printf("[+] Tunnel connected")

	// Jalankan suntik payload jika masuk mode "payload" ATAU "tlsmod"
	if cfg.Mode == "payload" || cfg.Mode == "tlsmod" {
		payload := buildPayload(cfg.Payload, cfg.ServerHost, cfg.ServerPort)

		if cfg.Debug {
			log.Println("========== PAYLOAD ==========")
			log.Println(payload)
			log.Println("=============================")
		}

		err = sendSplitPayload(remote, payload)
		if err != nil {
			log.Printf("[-] Payload gagal dikirim: %v", err)
			client.Close()
			remote.Close()
			return
		}

		log.Printf("[+] Payload terkirim")

		reader := bufio.NewReader(remote)
		resp, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[-] Gagal membaca response: %v", err)
			client.Close()
			remote.Close()
			return
		}

		resp = strings.TrimSpace(resp)
		log.Printf("[+] Response: %s", resp)

		if !validateResponse(resp) {
			log.Printf("[-] Payload ditolak server")
			client.Close()
			remote.Close()
			return
		}

		log.Printf("[+] Payload accepted")
	}

	go pipe(client, remote, "REMOTE -> CLIENT")
	go pipe(remote, client, "CLIENT -> REMOTE")

	log.Printf("[+] Session started -> %s", clientAddr)
}

func startSSH(cfg *Config) {
	time.Sleep(1 * time.Second)

	for {
		reconnectMutex.Lock()
		log.Println("[*] Menjalankan SSH Core...")

		cmd := exec.Command(
			"sshpass",
			"-p", cfg.SSHPassword,
			"ssh",
			"-N",
			"-D", "0.0.0.0:1080",
			"-p", cfg.ListenPort,
			fmt.Sprintf("%s@127.0.0.1", cfg.SSHUser),
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "ServerAliveInterval=20",
			"-o", "ServerAliveCountMax=3",
			"-o", "TCPKeepAlive=yes",
			"-o", "ConnectTimeout=10",
			"-o", "ExitOnForwardFailure=yes",
		)

		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		fmt.Println("========================================")
		fmt.Println(" SOCKS5 READY -> 127.0.0.1:1080")
		fmt.Println("========================================")

		err := cmd.Run()
		if err != nil {
			log.Printf("[-] SSH Disconnect: %v", err)
		}

		reconnectMutex.Unlock()
		log.Println("[*] Reconnect dalam 5 detik...")
		time.Sleep(5 * time.Second)
	}
}

func main() {
	log.Println("========================================")
	log.Println(" GO HTTP INJECTOR STYLE ENGINE")
	log.Println("========================================")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%s", cfg.ListenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Listen error: %v", err)
	}
	defer listener.Close()

	log.Printf("[+] Local Tunnel : %s", listenAddr)
	log.Printf("[+] Mode          : %s", strings.ToUpper(cfg.Mode))
	log.Printf("[+] SNI          : %s", cfg.SNIHost)

	go startSSH(cfg)

	for {
		client, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleClient(client, cfg)
	}
}