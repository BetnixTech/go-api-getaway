package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// JWT secret
var jwtSecret = []byte("supersecretkey")

// Microservice registry (serviceName -> list of URLs)
var services = map[string][]string{
	"service1": {"http://localhost:9001", "http://localhost:9003"},
	"service2": {"http://localhost:9002"},
}

// Load balancer counters
var lbCounter = make(map[string]int)
var lbMutex = sync.Mutex{}

// Rate limiting (requests per IP per minute)
var rateLimit = 20
var clients = make(map[string]int)
var clientsMutex = sync.Mutex{}

// Middleware: Logging
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
	})
}

// Middleware: JWT
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware: Simple rate limiting
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]
		clientsMutex.Lock()
		count := clients[ip]
		if count >= rateLimit {
			clientsMutex.Unlock()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		clients[ip] = count + 1
		clientsMutex.Unlock()
		next.ServeHTTP(w, r)
	})
}

// Reset rate limits every minute
func rateLimitReset() {
	for {
		time.Sleep(time.Minute)
		clientsMutex.Lock()
		clients = make(map[string]int)
		clientsMutex.Unlock()
	}
}

// JWT login handler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	type creds struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	var c creds
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": c.User,
		"exp":  time.Now().Add(time.Hour * 1).Unix(),
	})
	tokenStr, _ := token.SignedString(jwtSecret)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}

// Health check
func healthHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Dynamic proxy with load balancing
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	service := vars["service"]
	instances, ok := services[service]
	if !ok || len(instances) == 0 {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}

	// Round-robin load balancing
	lbMutex.Lock()
	target := instances[lbCounter[service]%len(instances)]
	lbCounter[service]++
	lbMutex.Unlock()

	// Forward request
	body, _ := io.ReadAll(r.Body)
	proxyReq, err := http.NewRequest(r.Method, target+r.RequestURI, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}
	for k, v := range r.Header {
		proxyReq.Header[k] = v
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Failed to reach service", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// Dashboard showing service list
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	dashboard := map[string]interface{}{}
	for svc, inst := range services {
		dashboard[svc] = map[string]interface{}{
			"instances": inst,
			"lbIndex":   lbCounter[svc],
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboard)
}

func main() {
	// Start rate limit reset routine
	go rateLimitReset()

	r := mux.NewRouter()
	r.Use(loggingMiddleware)
	r.Use(rateLimitMiddleware)

	// Public routes
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/dashboard", dashboardHandler).Methods("GET")

	// Protected proxy routes
	api := r.PathPrefix("/api/{service}").Subrouter()
	api.Use(jwtMiddleware)
	api.PathPrefix("/").HandlerFunc(proxyHandler)

	fmt.Println("Full-featured API Gateway running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
