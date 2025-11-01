package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const name = "httpbin"

const version = "0.0.0"

var revision = "HEAD"

const bodyKey = "body"

type statusResponseWriter struct {
	http.ResponseWriter
	status      int
	written     int
	contentType string
}

func (srw *statusResponseWriter) WriteHeader(code int) {
	if status := srw.status; status < 100 || status >= 400 {
		// Only write header if not already written or error
		srw.status = code
		srw.ResponseWriter.WriteHeader(code)
	}
}

func (srw *statusResponseWriter) Write(b []byte) (int, error) {
	if srw.written == 0 && srw.status == 0 {
		srw.status = 200
	}
	srw.written += len(b)
	return srw.ResponseWriter.Write(b)
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func getProtocol(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func bodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength == 0 || r.Body == nil {
			ctx := context.WithValue(r.Context(), bodyKey, "")
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		r.Body.Close()

		var decompressed []byte
		if r.Header.Get("Content-Encoding") == "gzip" {
			gr, err := gzip.NewReader(bytes.NewReader(bodyBytes))
			if err != nil {
				http.Error(w, "Failed to decompress gzip", http.StatusBadRequest)
				return
			}
			defer gr.Close()
			decompressed, err = io.ReadAll(gr)
			if err != nil {
				http.Error(w, "Failed to read decompressed body", http.StatusBadRequest)
				return
			}
		} else {
			decompressed = bodyBytes
		}

		bodyStr := string(decompressed)
		newBody := io.NopCloser(bytes.NewReader(decompressed))
		r.Body = newBody
		ctx := context.WithValue(r.Context(), bodyKey, bodyStr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		srw := &statusResponseWriter{ResponseWriter: w, status: 0}
		next.ServeHTTP(srw, r)
		duration := time.Since(start)

		remoteAddr := getClientIP(r)
		remoteUser := "-"
		if auth := r.Header.Get("Authorization"); auth != "" {
			// Basic auth approximation
			if strings.HasPrefix(auth, "Basic ") {
				remoteUser = "user" // placeholder
			}
		}
		dateStr := start.Format("02/Jan/2006:15:04:05 -0700")
		reqURL := r.URL.RequestURI()
		status := srw.status
		if status == 0 {
			status = 200
		}
		contentLen := "-"
		if cl := r.Header.Get("Content-Length"); cl != "" {
			contentLen = cl
		} else if srw.written > 0 {
			contentLen = strconv.Itoa(srw.written)
		}
		referrer := r.Referer()
		if referrer == "" {
			referrer = "-"
		}
		userAgent := r.UserAgent()
		if userAgent == "" {
			userAgent = "-"
		}

		log.Printf("%s - %s [%s] \"%s %s %s\" %d %s \"%s\" \"%s\" %s",
			remoteAddr, remoteUser, dateStr, r.Method, reqURL, r.Proto,
			status, contentLen, referrer, userAgent, duration)
	})
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	bodyStr, _ := r.Context().Value(bodyKey).(string)

	echo := map[string]interface{}{
		"path":     r.URL.Path,
		"headers":  r.Header,
		"method":   r.Method,
		"body":     bodyStr,
		"hostname": r.Host,
		"protocol": getProtocol(r),
		"query":    r.URL.Query(),
		"xhr":      r.Header.Get("X-Requested-With") == "XMLHttpRequest",
	}

	// Cookies
	cookies := make(map[string]string)
	for _, c := range r.Cookies() {
		cookies[c.Name] = c.Value
	}
	echo["cookies"] = cookies

	// Fresh (approximation)
	echo["fresh"] = false

	// IP and IPS
	xff := r.Header.Get("X-Forwarded-For")
	ips := make([]string, 0)
	if xff != "" {
		parts := strings.Split(xff, ",")
		for _, p := range parts {
			ips = append(ips, strings.TrimSpace(p))
		}
	}
	echo["ips"] = ips
	if len(ips) > 0 {
		echo["ip"] = ips[0]
	} else {
		echo["ip"] = getClientIP(r)
	}

	// Subdomains (rough)
	parts := strings.Split(r.Host, ".")
	if len(parts) > 2 {
		echo["subdomains"] = parts[:len(parts)-2]
	} else {
		echo["subdomains"] = []string{}
	}

	// OS
	hostname, _ := os.Hostname()
	echo["os"] = map[string]string{"hostname": hostname}

	// Connection
	echo["connection"] = map[string]string{"servername": r.Host}

	// Client certificate
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		echo["clientCertificate"] = map[string]interface{}{
			"subject":      cert.Subject.String(),
			"issuer":       cert.Issuer.String(),
			"serialNumber": cert.SerialNumber.String(),
			"notBefore":    cert.NotBefore,
			"notAfter":     cert.NotAfter,
			// Add more fields as needed
		}
	}

	// JSON parse
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var jsonData interface{}
		if err := json.Unmarshal([]byte(bodyStr), &jsonData); err == nil {
			echo["json"] = jsonData
		} else {
			log.Printf("Invalid JSON Body received with Content-Type: %s: %v", contentType, err)
		}
	}

	// Set status
	statusStr := r.Header.Get("X-Set-Response-Status-Code")
	if statusStr == "" {
		statusStr = r.URL.Query().Get("x-set-response-status-code")
	}
	if status, err := strconv.Atoi(statusStr); err == nil && 100 <= status && status < 600 {
		w.WriteHeader(status)
	}

	// Delay
	delayStr := r.Header.Get("X-Set-Response-Delay-Ms")
	if delay, err := strconv.ParseInt(delayStr, 10, 64); err == nil && delay > 0 {
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	// Content-Type
	ct := r.Header.Get("X-Set-Response-Content-Type")

	// CORS
	if origin := os.Getenv("CORS_ALLOW_ORIGIN"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		if methods := os.Getenv("CORS_ALLOW_METHODS"); methods != "" {
			w.Header().Set("Access-Control-Allow-Methods", methods)
		}
		if headers := os.Getenv("CORS_ALLOW_HEADERS"); headers != "" {
			w.Header().Set("Access-Control-Allow-Headers", headers)
		}
		if creds := os.Getenv("CORS_ALLOW_CREDENTIALS"); creds != "" {
			w.Header().Set("Access-Control-Allow-Credentials", creds)
		}
	}

	// Full echo
	if ct == "" {
		w.Header().Set("Content-Type", "application/json")
	}

	data, _ := json.MarshalIndent(echo, "", "  ")
	w.Write(data)
}

func main() {
	// Env vars
	maxHeaderSizeStr := os.Getenv("MAX_HEADER_SIZE")
	maxHeaderSize, err := strconv.Atoi(maxHeaderSizeStr)
	if err != nil {
		maxHeaderSize = 1048576
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{path...}", echoHandler)

	var handler http.Handler = mux

	// Logging
	if os.Getenv("DISABLE_REQUEST_LOGS") != "true" {
		handler = loggingMiddleware(handler)
	}

	// Body middleware
	handler = bodyMiddleware(handler)

	// Servers
	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           handler,
		ReadHeaderTimeout: time.Second * 60,
		MaxHeaderBytes:    maxHeaderSize,
	}

	// Start servers
	log.Printf("Listening on port %s for http", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}
}
