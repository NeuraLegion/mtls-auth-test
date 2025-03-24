package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// LoadClientCerts loads client certificates from provided paths
func LoadClientCerts(certPaths []string) (*tls.Config, error) {
	certPool := x509.NewCertPool()

	for _, certPath := range certPaths {
		// Load client certificate file
		certData, err := ioutil.ReadFile(certPath)
		if err != nil {
			log.Printf("Failed to read certificate: %s\n", certPath)
			return nil, err
		}

		// Append client certificate to pool
		if ok := certPool.AppendCertsFromPEM(certData); !ok {
			log.Printf("Failed to append cert for %s", certPath)
			return nil, fmt.Errorf("failed to append certificate")
		}
	}

	// Configure mTLS with Client Cert Validation
	tlsConfig := &tls.Config{
		ClientCAs:  certPool,
		ClientAuth: tls.RequireAndVerifyClientCert, // Require a valid client certificate
	}
	return tlsConfig, nil
}

func secureHandler(w http.ResponseWriter, r *http.Request) {
	clientCert := r.TLS.PeerCertificates[0] // Get the client certificate
	fmt.Fprintf(w, "Hello, Secure World! Authenticated CN: %s", clientCert.Subject.CommonName)
}

func main() {
	// Define test certs
	certConfigs := []string{
	     "./client.pem",
	}

	tlsConfig, err := LoadClientCerts(certConfigs)
	if err != nil {
		log.Fatalf("Failed to load client certs: %v", err)
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(secureHandler),
	}

	log.Println("Starting mTLS API on https://localhost:8443")
	err = server.ListenAndServeTLS("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Server failed: %s", err)
	}
}
