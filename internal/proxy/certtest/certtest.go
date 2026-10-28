// Package certtest creates certificate chains for tests.
package certtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// CA is a test certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  string
}

// Leaf describes a certificate to issue.
type Leaf struct {
	Names     []string // DNS names or IP addresses
	NotBefore time.Time
	NotAfter  time.Time
	IsCA      bool
	ExtUsage  []x509.ExtKeyUsage // default: server authentication
}

func encode(typ string, b []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}))
}

var serial int64

func create(t testing.TB, tmpl, parent *x509.Certificate, pub, signer any) *x509.Certificate {
	t.Helper()
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// NewCA creates a self-signed root, or an intermediate when parent is set.
func NewCA(t testing.TB, name string, parent *CA) *CA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-30 * 24 * time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.Cert, parent.Key
	}
	c := create(t, tmpl, signerCert, &key.PublicKey, signerKey)
	return &CA{Cert: c, Key: key, PEM: encode("CERTIFICATE", c.Raw)}
}

// Issue returns the leaf certificate PEM and its PKCS#8 key PEM.
func (ca *CA) Issue(t testing.TB, l Leaf) (certPEM, keyPEM string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if l.NotBefore.IsZero() {
		l.NotBefore = time.Now().Add(-time.Hour)
	}
	if l.NotAfter.IsZero() {
		l.NotAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	if l.ExtUsage == nil {
		l.ExtUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, NotBefore: l.NotBefore, NotAfter: l.NotAfter, ExtKeyUsage: l.ExtUsage,
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: l.IsCA}
	for _, n := range l.Names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	c := create(t, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encode("CERTIFICATE", c.Raw), encode("PRIVATE KEY", der)
}
