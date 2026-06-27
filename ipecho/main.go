// ipecho —— 一个极简的 "返回调用方公网 IP" 服务，行为对标 `curl ip.sb`。
//
// 在 ipgate 场景里它是配套小工具：用户要把自己的 IP 加进放行名单前，
// 得先知道自己的出口 IP。直接 `curl https://你的域名/` 即可拿到。
//
// 默认只信任 TCP 连接来源（RemoteAddr），不读任何代理头——这是安全默认值，
// 因为返回的 IP 可能被拿去放行，绝不能让客户端用伪造的 X-Forwarded-For 骗到。
// 如果本服务跑在反向代理（nginx / Caddy / CDN）后面，用 -trusted-proxies N
// 显式声明前面有几层可信代理，才会去解析 X-Forwarded-For。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", envOr("IPECHO_ADDR", ":8080"), "监听地址 (host:port)")
	trustedProxies := flag.Int("trusted-proxies", envOrInt("IPECHO_TRUSTED_PROXIES", 0),
		"本服务前面的可信反向代理层数；>0 才解析 X-Forwarded-For，否则只用连接来源 IP")
	flag.Parse()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           newMux(*trustedProxies),
		ReadHeaderTimeout: 5 * time.Second, // 防 Slowloris
		IdleTimeout:       60 * time.Second,
	}

	// 优雅退出：收到信号后给在途请求 5 秒收尾。
	idleClosed := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("关闭出错: %v", err)
		}
		close(idleClosed)
	}()

	log.Printf("ipecho 监听 %s (trusted-proxies=%d)", *addr, *trustedProxies)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("启动失败: %v", err)
	}
	<-idleClosed
	log.Print("已退出")
}

func newMux(trustedProxies int) http.Handler {
	mux := http.NewServeMux()

	// 健康检查，给反代 / 编排用。
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	// 强制 JSON 输出，方便客户端程序解析。
	mux.HandleFunc("GET /json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, clientIP(r, trustedProxies))
	})

	// 根路由：内容协商。
	//   - 带 ?format=json，或 Accept 里要 JSON → 返回 JSON
	//   - 其余（curl、浏览器地址栏）→ 纯文本 IP + 换行，对标 ip.sb
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		ip := clientIP(r, trustedProxies)
		if wantsJSON(r) {
			writeJSON(w, ip)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, ip)
	})

	return logRequests(mux)
}

// clientIP 解析调用方 IP。
//
// trustedProxies==0：只认 TCP 连接来源，忽略一切代理头（安全默认）。
// trustedProxies==N>0：信任前面恰好 N 层代理，从 X-Forwarded-For 右侧
// 数到第 N 层之外的那一跳即真实客户端——右侧 N 个条目是可信代理留下的，
// 客户端只能伪造更左侧的，骗不过来。链路不够长（条目数 < N）则回退到连接来源。
func clientIP(r *http.Request, trustedProxies int) string {
	if trustedProxies > 0 {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := splitTrim(xff)
			idx := len(parts) - trustedProxies
			if idx >= 0 && idx < len(parts) {
				if ip := normalizeIP(parts[idx]); ip != "" {
					return ip
				}
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // 没端口就原样用
	}
	if ip := normalizeIP(host); ip != "" {
		return ip
	}
	return host
}

func wantsJSON(r *http.Request) bool {
	if f := r.URL.Query().Get("format"); strings.EqualFold(f, "json") {
		return true
	}
	// 简单判断：Accept 里出现 application/json 且不是 curl 那种 */*。
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

func writeJSON(w http.ResponseWriter, ip string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	payload := map[string]any{"ip": ip}
	if p := net.ParseIP(ip); p != nil {
		if p.To4() != nil {
			payload["family"] = "ipv4"
		} else {
			payload["family"] = "ipv6"
		}
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// normalizeIP 校验并规范化一个 IP 字面量；非法返回空串。
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	// XFF 里偶尔带端口或方括号，剥一下再解析。
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

func splitTrim(s string) []string {
	raw := strings.Split(s, ",")
	out := raw[:0]
	for _, p := range raw {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// logRequests 打一行精简访问日志。
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s (%s)", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start).Round(time.Microsecond))
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
