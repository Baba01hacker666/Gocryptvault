package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PKIBundle holds paths to all generated PKI files.
type PKIBundle struct {
	CAKey    string
	CACert   string
	SrvKey   string
	SrvCert  string
	NodeKey  string
	NodeCert string
}

// PKIOptions allows the caller to supply extra SANs / IPs for generated certs.
// FIXED HIGH-08: caller can pass real external hostnames/IPs so certs work
// beyond localhost deployments.
type PKIOptions struct {
	// ExtraSANs are additional DNS names to include in server/node certs.
	ExtraSANs []string
	// ExtraIPs are additional IP addresses to include in server/node certs.
	ExtraIPs []net.IP
	// CACertValidity controls how long the CA cert is valid (default: 2 years).
	CACertValidity time.Duration
	// LeafCertValidity controls how long leaf certs are valid (default: 90 days).
	LeafCertValidity time.Duration
}

func defaultOpts() PKIOptions {
	return PKIOptions{
		CACertValidity:  2 * 365 * 24 * time.Hour,  // 2 years (was 10)
		LeafCertValidity: 90 * 24 * time.Hour,       // 90 days (was 5 years)
	}
}

// EnsurePKI checks if the PKI bundle exists in dir; if not, generates a fresh
// CA, server cert, and node cert all signed by the CA. This means users never
// have to manually run openssl or provide cert paths.
//
// FIXED HIGH-02: CA lifetime reduced to 2 years, leaf to 90 days.
// FIXED HIGH-08: accepts PKIOptions with extra SANs/IPs for real deployments.
// FIXED MED-08: validates existing certs are not expired and key-matches cert.
func EnsurePKI(dir string, opts *PKIOptions) (*PKIBundle, error) {
	if opts == nil {
		o := defaultOpts()
		opts = &o
	}
	if opts.CACertValidity == 0 {
		opts.CACertValidity = 2 * 365 * 24 * time.Hour
	}
	if opts.LeafCertValidity == 0 {
		opts.LeafCertValidity = 90 * 24 * time.Hour
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create pki dir: %w", err)
	}

	bundle := &PKIBundle{
		CAKey:    filepath.Join(dir, "ca.key"),
		CACert:   filepath.Join(dir, "ca.crt"),
		SrvKey:   filepath.Join(dir, "server.key"),
		SrvCert:  filepath.Join(dir, "server.crt"),
		NodeKey:  filepath.Join(dir, "node.key"),
		NodeCert: filepath.Join(dir, "node.crt"),
	}

	// FIXED MED-08: validate existing certs before trusting them.
	if allExist(bundle.CACert, bundle.SrvKey, bundle.SrvCert, bundle.NodeKey, bundle.NodeCert) {
		if certValid(bundle.SrvCert, bundle.SrvKey) && certValid(bundle.NodeCert, bundle.NodeKey) {
			return bundle, nil
		}
		fmt.Println("[pki] Existing certificates are expired or invalid — regenerating...")
	}

	fmt.Println("[pki] Generating PKI (CA + server + node certificates)...")

	// 1. Generate CA key pair
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	// FIXED MED-07: propagate bigRand errors
	serial, err := bigRand()
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Gocryptvault-CA", Organization: []string{"Gocryptvault"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(opts.CACertValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	if err := writeKey(bundle.CAKey, caKey); err != nil {
		return nil, err
	}
	if err := writeCert(bundle.CACert, caDER); err != nil {
		return nil, err
	}

	// Base SANs always include localhost; merge caller-supplied extras.
	// FIXED HIGH-08: extra SANs/IPs included for real network deployments.
	baseSANs := append([]string{"localhost", "coordinator"}, opts.ExtraSANs...)
	baseIPs := append([]net.IP{net.ParseIP("127.0.0.1")}, opts.ExtraIPs...)

	// 2. Generate server cert signed by CA (OU=coordinator for role-based auth)
	if err := signAndWrite(caCert, caKey, "coordinator", "coordinator",
		bundle.SrvKey, bundle.SrvCert, baseSANs, baseIPs, opts.LeafCertValidity); err != nil {
		return nil, fmt.Errorf("server cert: %w", err)
	}

	// 3. Generate node cert signed by CA (OU=node for role-based auth)
	nodeSANs := append([]string{"localhost", "node"}, opts.ExtraSANs...)
	if err := signAndWrite(caCert, caKey, "node", "node",
		bundle.NodeKey, bundle.NodeCert, nodeSANs, baseIPs, opts.LeafCertValidity); err != nil {
		return nil, fmt.Errorf("node cert: %w", err)
	}

	fmt.Printf("[pki] Certificates written to: %s\n", dir)
	return bundle, nil
}

// LoadOrGenTLSConfig is a convenience wrapper: it calls EnsurePKI if needed,
// then loads the TLS config automatically.
func LoadOrGenTLSConfig(pkiDir string, isServer bool, opts *PKIOptions) (*tls.Config, *PKIBundle, error) {
	bundle, err := EnsurePKI(pkiDir, opts)
	if err != nil {
		return nil, nil, err
	}

	certFile, keyFile := bundle.SrvCert, bundle.SrvKey
	if !isServer {
		certFile, keyFile = bundle.NodeCert, bundle.NodeKey
	}

	cfg, err := LoadTLSConfig(bundle.CACert, certFile, keyFile, isServer)
	if err != nil {
		return nil, nil, err
	}
	return cfg, bundle, nil
}

// --- helpers ---

// signAndWrite creates a leaf cert signed by caCert/caKey and writes the PEM
// key and cert files. The ou parameter sets the cert's OU for role-based auth.
func signAndWrite(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn, ou, keyPath, certPath string, sans []string, ips []net.IP, validity time.Duration) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// FIXED MED-07: propagate bigRand errors
	serial, err := bigRand()
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Gocryptvault"},
			// FIXED CRIT-04: embed role in OU so coordinator can enforce RBAC
			OrganizationalUnit: []string{ou},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    sans,
		IPAddresses: ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	if err := writeKey(keyPath, key); err != nil {
		return err
	}
	return writeCert(certPath, der)
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(path, "EC PRIVATE KEY", der, 0600)
}

func writeCert(path string, der []byte) error {
	return writePEM(path, "CERTIFICATE", der, 0644)
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

// FIXED MED-07: bigRand now returns an error instead of silently discarding it.
func bigRand() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("entropy source failed: %w", err)
	}
	return n, nil
}

func allExist(paths ...string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// FIXED MED-08: certValid checks the cert file is parseable, not expired,
// and that the private key matches the public key in the cert.
func certValid(certPath, keyPath string) bool {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return false
	}
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	// Reject certs that expire within the next 7 days
	if time.Now().After(x509Cert.NotAfter.Add(-7 * 24 * time.Hour)) {
		return false
	}
	return true
}
