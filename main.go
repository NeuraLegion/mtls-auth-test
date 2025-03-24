package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
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

var (
	certsDir = flag.String("certs", ".", "certificate directory")
	addr     = flag.String("addr", ":8443", "server address")
)

func main() {
	flag.Parse()

	// Define test certs
	certConfigs := []string{
		*certsDir + "/client.pem",
	}

	tlsConfig, err := LoadClientCerts(certConfigs)
	if err != nil {
		log.Fatalf("Failed to load client certs: %v", err)
	}

	server := &http.Server{
		Addr:      *addr,
		TLSConfig: tlsConfig,
		Handler:   http.HandlerFunc(secureHandler),
	}

	log.Println("Starting mTLS API on https://" + *addr)
	err = server.ListenAndServeTLS(*certsDir+"/server.crt", *certsDir+"/server.key")
	if err != nil {
		log.Fatalf("Server failed: %s", err)
	}
}
