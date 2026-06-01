package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTempCerts(t *testing.T) (caFile, certFile, keyFile string) {
	tempDir := t.TempDir()

	// CA
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Gocryptvault CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	caFile = filepath.Join(tempDir, "ca.crt")
	caOut, _ := os.Create(caFile)
	pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	caOut.Close()

	// Cert/Key
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Gocryptvault Node"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, caTemplate, &privKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	certFile = filepath.Join(tempDir, "cert.crt")
	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	certOut.Close()

	keyFile = filepath.Join(tempDir, "key.pem")
	keyOut, _ := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	keyOut.Close()

	return
}

func TestLoadTLSConfig(t *testing.T) {
	caFile, certFile, keyFile := generateTempCerts(t)

	t.Run("Server Config", func(t *testing.T) {
		cfg, err := LoadTLSConfig(caFile, certFile, keyFile, true)
		if err != nil {
			t.Fatalf("LoadTLSConfig failed: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
		// Basic checks
		if len(cfg.Certificates) != 1 {
			t.Errorf("expected 1 cert, got %d", len(cfg.Certificates))
		}
	})

	t.Run("Client Config", func(t *testing.T) {
		cfg, err := LoadTLSConfig(caFile, certFile, keyFile, false)
		if err != nil {
			t.Fatalf("LoadTLSConfig failed: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
	})

	t.Run("Missing Files", func(t *testing.T) {
		_, err := LoadTLSConfig("nonexistent", certFile, keyFile, false)
		if err == nil {
			t.Error("expected error for missing CA file")
		}
	})
}
