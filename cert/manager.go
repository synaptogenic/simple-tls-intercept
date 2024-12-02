package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type Manager struct {
	configPath string
	certPath   string
	keyPath    string

	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func (m *Manager) InstallCA() error {
	// Populate paths to CA files
	var err error
	m.configPath, m.keyPath, m.certPath, err = getCertKeyPaths()
	if err != nil {
		return err
	}

	// Get CA from disk or generate/store it
	err = m.loadOrGenerateCA()
	if err != nil {
		return err
	}

	// install CA cert into keychain
	err = m.ensureCAIsInstalled()
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) UntrustCA() error {
	// TODO: figure out how to do this
	return nil
}

func (m *Manager) loadOrGenerateCA() (err error) {
	defer func() {
		if err == nil {
			if m.cert == nil {
				err = errors.New("cert was nil")
			}
			if m.key == nil {
				err = errors.New("key was nil")
			}
		}
	}()

	if m.caExists() {
		log.Print("Loading previously generated CA cert/key from disk")
		return m.loadCA()
	} else {
		log.Print("Generating new CA cert/key")
		return m.generateCA()
	}

	return nil
}

func (m *Manager) caExists() bool {
	// See if CA cert/key exists already
	if _, err := os.Stat(m.keyPath); err != nil {
		return false
	}
	if _, err := os.Stat(m.certPath); err != nil {
		return false
	}
	return true
}

func (m *Manager) loadCA() error {
	// Read the certificate file
	certBytes, err := ioutil.ReadFile(m.certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Decode the cert
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM block")
	}

	// Parse the certificate
	m.cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Read the private key file
	keyBytes, err := ioutil.ReadFile(m.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}

	// Decode the private key
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM block")
	}

	// Parse the private key
	m.key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse ECDSA private key: %v", err)
	}
	return nil
}

func (m *Manager) generateCA() error {
	// Create config dir if it doesn't already exist
	err := os.MkdirAll(m.configPath, 0700)
	if err != nil {
		return err
	}

	// Generate ECDSA Private Key
	m.key, err = generateECDSAKey()
	if err != nil {
		return fmt.Errorf("error generating ECDSA key: %v", err)
	}

	// Generate Self-Signed CA Certificate
	var certBytes []byte
	m.cert, certBytes, err = generateSelfSignedCACertificate(m.key)
	if err != nil {
		return fmt.Errorf("error generating CA certificate: %v", err)
	}

	// Save the Certificate and Private Key to PEM files
	err = savePEMFile(m.certPath, "CERTIFICATE", certBytes)
	if err != nil {
		return fmt.Errorf("error saving certificate: %v", err)
	}

	privKeyBytes, err := x509.MarshalECPrivateKey(m.key)
	if err != nil {
		return fmt.Errorf("error marshaling private key: %v", err)
	}

	err = savePEMFile(m.keyPath, "EC PRIVATE KEY", privKeyBytes)
	if err != nil {
		return fmt.Errorf("error saving private key: %v", err)
	}
	return nil
}

func (m *Manager) ensureCAIsInstalled() error {
	if runtime.GOOS != "darwin" {
		log.Printf("You are not running on macOS so you will need to manually install the CA cert into your trust store. You can find the CA cert at: %s", m.certPath)
		return nil
	}

	// Run the security command to detect if the CA cert is in the system keychain
	cmd := exec.Command(
		"security",
		"find-certificate",
		"-c", "SimpleTLSIntercept CA",
		"/Library/Keychains/System.keychain",
	)
	err := cmd.Run()
	if err == nil {
		// CA cert is already installed
		log.Printf("CA cert is already installed into the system keychain")
		return nil
	}
	var errCode *exec.ExitError
	if err != nil && !errors.As(err, &errCode) {
		return fmt.Errorf("failed to check if certificate is in the keychain: %v", err)
	}

	log.Printf("Installing CA cert into the system keychain, this requires sudo permissions")
	// Run the security command to add the certificate to the system keychain
	cmd = exec.Command(
		"sudo",
		"security",
		"add-trusted-cert",
		"-d",
		"-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain",
		m.certPath,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install certificate into keychain: %v, %s", err, output)
	}

	log.Printf("Installed CA cert into the system keychain")
	return nil
}

func getCertKeyPaths() (string, string, string, error) {
	// Get OS specific config directory
	configPath, err := os.UserConfigDir()
	if err != nil {
		return "", "", "", err
	}

	// Paths
	configPath = filepath.Join(configPath, "simple-tls-intercept")
	keyPath := filepath.Join(configPath, "ca.key")
	certPath := filepath.Join(configPath, "ca.crt")

	return configPath, keyPath, certPath, nil
}

// generateECDSAKey generates a new ECDSA private key using the P-256 curve
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	// Use the P-256 curve (the most commonly used curve)
	curve := elliptic.P256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// generateSelfSignedCACertificate generates a self-signed CA certificate and returns the certificate
func generateSelfSignedCACertificate(privateKey *ecdsa.PrivateKey) (*x509.Certificate, []byte, error) {
	// Define the certificate template (self-signed CA)
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year validity

	certTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "SimpleTLSIntercept CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	// Sign the certificate using the private key (self-signed)
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DER certificate: %v", err)
	}

	return cert, certDER, nil
}

// savePEMFile saves the given data to a file in PEM format
func savePEMFile(fileName, pemType string, data []byte) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pem.Block{Type: pemType, Bytes: data})
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) GenerateCerts(domains []string) ([]tls.Certificate, error) {
	var certs []tls.Certificate
	for _, domain := range domains {
		cert, err := generateServerCert(domain, m.cert, m.key)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func generateServerCert(domain string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (tls.Certificate, error) {
	// Generate a new private key for the server
	serverKey, err := generateECDSAKey()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error generating server private ECDSA key: %v", err)
	}

	// Create a certificate template for the server
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour) // 1 day validity

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"simple-tls-intercept"},
			CommonName:   domain,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	// Sign the certificate with the CA's private key
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to sign server certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Convert the private key to DER-encoded bytes
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to convert server key to DER", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return tls.X509KeyPair(certPEM, keyPEM)
}
