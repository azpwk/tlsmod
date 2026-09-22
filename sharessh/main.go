package main

import (
	"bufio"
	// "fmt"
	"io"
	"log"
	// "net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const (
	listenAddress = "192.168.0.200:8080"
	socks5Address = "127.0.0.1:1080"
)

func main() {
	// Membuat dialer SOCKS5.
	socksDialer, err := proxy.SOCKS5(
		"tcp",
		socks5Address,
		nil,
		proxy.Direct,
	)
	if err != nil {
		log.Fatalf("gagal membuat SOCKS5 dialer: %v", err)
	}

	server := &http.Server{
		Addr:              listenAddress,
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleHTTPS(w, r, socksDialer)
				return
			}

			handleHTTP(w, r, socksDialer)
		}),
	}

	log.Printf("HTTP proxy listen di %s", listenAddress)
	log.Printf("Meneruskan ke SOCKS5 %s", socks5Address)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// Menangani HTTPS.
// Browser/HP mengirim:
//
// CONNECT example.com:443 HTTP/1.1
//
// Setelah itu proxy membuat tunnel TCP dan menyalin data dua arah.
func handleHTTPS(
	w http.ResponseWriter,
	r *http.Request,
	socksDialer proxy.Dialer,
) {
	target := r.Host

	if target == "" {
		http.Error(w, "alamat tujuan kosong", http.StatusBadRequest)
		return
	}

	log.Printf("CONNECT %s", target)

	targetConn, err := socksDialer.Dial("tcp", target)
	if err != nil {
		log.Printf("gagal konek ke %s melalui SOCKS5: %v", target, err)
		http.Error(w, "gagal terhubung ke tujuan", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Ambil koneksi TCP asli milik client.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server tidak mendukung hijacking", http.StatusInternalServerError)
		return
	}

	clientConn, clientReadWriter, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "gagal membuka tunnel", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Beri tahu HP bahwa tunnel HTTPS berhasil.
	_, err = clientReadWriter.WriteString(
		"HTTP/1.1 200 Connection Established\r\n\r\n",
	)
	if err != nil {
		return
	}

	if err := clientReadWriter.Flush(); err != nil {
		return
	}

	// Salin data dua arah.
	go func() {
		_, _ = io.Copy(targetConn, clientConn)
	}()

	_, _ = io.Copy(clientConn, targetConn)
}

// Menangani HTTP biasa, misalnya:
//
// GET http://example.com/path HTTP/1.1
func handleHTTP(
	w http.ResponseWriter,
	r *http.Request,
	socksDialer proxy.Dialer,
) {
	if r.URL.Host == "" {
		http.Error(w, "URL proxy tidak valid", http.StatusBadRequest)
		return
	}

	target := r.URL.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	log.Printf("%s %s", r.Method, r.URL.String())

	targetConn, err := socksDialer.Dial("tcp", target)
	if err != nil {
		log.Printf("gagal konek ke %s melalui SOCKS5: %v", target, err)
		http.Error(w, "gagal terhubung ke tujuan", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Proxy HTTP perlu mengirim request-target berupa path,
	// bukan URL lengkap.
	r.RequestURI = r.URL.RequestURI()
	r.URL.Scheme = ""
	r.URL.Host = ""

	// Header proxy tidak perlu diteruskan ke server tujuan.
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Connection")

	// Tulis request ke koneksi SOCKS5.
	if err := r.Write(targetConn); err != nil {
		http.Error(w, "gagal mengirim request", http.StatusBadGateway)
		return
	}

	// Baca response dari server tujuan.
	response, err := http.ReadResponse(
		bufio.NewReader(targetConn),
		r,
	)
	if err != nil {
		http.Error(w, "gagal membaca response", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	// Salin status, header, dan body response ke client.
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}
