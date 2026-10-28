package main

import (
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quvonchbek-devops/ipt-lens/internal/api"
	"github.com/quvonchbek-devops/ipt-lens/internal/iptables"
	"github.com/quvonchbek-devops/ipt-lens/web"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "bind manzili, masalan WireGuard IP: 10.8.0.1:8090")
	demo := flag.Bool("demo", false, "root bo'lmagan muhitda mock ma'lumot bilan ishlash (firewall o'zgarmaydi)")
	timeout := flag.Duration("rollback-timeout", 60*time.Second, "tasdiqlanmasa avtomatik qaytarish vaqti")
	stateDir := flag.String("state-dir", "/var/lib/ipt-lens", "backup va pending fayllar papkasi")
	flag.Parse()

	token := os.Getenv("IPTLENS_TOKEN")
	if token != "" && len(token) < 16 {
		log.Fatal("IPTLENS_TOKEN kamida 16 belgi bo'lishi kerak")
	}
	if !isLoopback(*listen) && token == "" {
		log.Fatal("tarmoqqa ochiq bind uchun IPTLENS_TOKEN majburiy")
	}

	watch, err := iptables.NewWatchdog(*stateDir, *demo, *timeout)
	if err != nil {
		log.Fatal(err)
	}

	static, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		log.Fatal(err)
	}

	srv := &api.Server{
		Demo:   *demo,
		Token:  token,
		Watch:  watch,
		Static: http.FileServer(http.FS(static)),
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("IPT-Lens ishga tushdi: http://%s (demo=%v, token=%v)", *listen, *demo, token != "")
	log.Fatal(httpSrv.ListenAndServe())
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
