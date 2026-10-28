package proxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"
)

// Certificate checks shared by the Core (uploads, AT-F12-03) and the proxy
// service, which checks every certificate again before Caddy gets it.

// Limits of a certificate chain and its key.
const (
	MaxChainCerts   = 10
	MaxPEMBytes     = 64 << 10
	MaxCertificates = 100
)

// KeyPair is a parsed certificate chain with its private key.
type KeyPair struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate // leaf first
	Key   crypto.Signer
}

// ParseKeyPair parses a PEM chain (leaf first) and an unencrypted PEM key
// and checks that the key belongs to the leaf and is strong enough.
func ParseKeyPair(certPEM, keyPEM string) (KeyPair, error) {
	if len(certPEM) > MaxPEMBytes || len(keyPEM) > MaxPEMBytes {
		return KeyPair{}, invalid("certificate and key may have at most %d KiB each", MaxPEMBytes>>10)
	}
	var kp KeyPair
	rest := []byte(certPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return KeyPair{}, invalid("the certificate file contains a %q block; only certificates are allowed there", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return KeyPair{}, invalid("a certificate cannot be parsed: %v", err)
		}
		kp.Chain = append(kp.Chain, c)
	}
	if len(kp.Chain) == 0 || strings.TrimSpace(string(rest)) != "" {
		return KeyPair{}, invalid("the certificate must be PEM (BEGIN CERTIFICATE), leaf first")
	}
	if len(kp.Chain) > MaxChainCerts {
		return KeyPair{}, invalid("at most %d certificates in a chain", MaxChainCerts)
	}
	kp.Leaf = kp.Chain[0]

	b, rest := pem.Decode([]byte(keyPEM))
	if b == nil || strings.TrimSpace(string(rest)) != "" {
		return KeyPair{}, invalid("the key must be a single PEM block")
	}
	if b.Type == "ENCRYPTED PRIVATE KEY" || b.Headers["Proc-Type"] != "" {
		return KeyPair{}, invalid("encrypted keys are not supported; remove the passphrase first")
	}
	var key any
	var err error
	switch b.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(b.Bytes)
	default:
		return KeyPair{}, invalid("unsupported key block %q", b.Type)
	}
	if err != nil {
		return KeyPair{}, invalid("the key cannot be parsed: %v", err)
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return KeyPair{}, invalid("RSA keys need at least 2048 bits")
		}
		kp.Key = k
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return KeyPair{}, invalid("ECDSA keys must use P-256 or P-384")
		}
		kp.Key = k
	case ed25519.PrivateKey:
		kp.Key = k
	default:
		return KeyPair{}, invalid("unsupported key type")
	}
	pub, ok := kp.Leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(kp.Key.Public()) {
		return KeyPair{}, invalid("the key does not belong to the certificate")
	}
	return kp, nil
}

// Covers reports whether the leaf is valid for host (SAN, one-label wildcard).
func Covers(leaf *x509.Certificate, host string) bool { return leaf.VerifyHostname(host) == nil }

// CertInfo describes a certificate without its key.
type CertInfo struct {
	Names     []string  `json:"names"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SHA256    string    `json:"sha256"`
}

// Info summarizes the leaf.
func (kp KeyPair) Info() CertInfo {
	names := append([]string{}, kp.Leaf.DNSNames...)
	for _, ip := range kp.Leaf.IPAddresses {
		names = append(names, ip.String())
	}
	sum := sha256.Sum256(kp.Leaf.Raw)
	return CertInfo{Names: names, Issuer: kp.Leaf.Issuer.String(), NotBefore: kp.Leaf.NotBefore.UTC(), NotAfter: kp.Leaf.NotAfter.UTC(), SHA256: hex.EncodeToString(sum[:])}
}

var weakSignatures = map[x509.SignatureAlgorithm]bool{
	x509.MD2WithRSA: true, x509.MD5WithRSA: true, x509.SHA1WithRSA: true, x509.DSAWithSHA1: true, x509.ECDSAWithSHA1: true,
}

// ValidateUpload adds the checks for uploaded certificates: validity,
// purpose, signatures and a chain to a trusted root. roots nil means the
// system roots; self-signed CA certificates in the upload are trusted too
// (an own CA).
func ValidateUpload(certPEM, keyPEM string, now time.Time, roots *x509.CertPool) (KeyPair, error) {
	kp, err := ParseKeyPair(certPEM, keyPEM)
	if err != nil {
		return kp, err
	}
	leaf := kp.Leaf
	switch {
	case now.Before(leaf.NotBefore):
		return kp, invalid("the certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	case now.Add(24 * time.Hour).After(leaf.NotAfter):
		return kp, invalid("the certificate expired or expires within a day (%s)", leaf.NotAfter.UTC().Format(time.RFC3339))
	case leaf.IsCA:
		return kp, invalid("the first certificate is a CA certificate, not a server certificate")
	case len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0:
		return kp, invalid("the certificate names no host (subject alternative names)")
	}
	for _, c := range kp.Chain {
		if weakSignatures[c.SignatureAlgorithm] {
			return kp, invalid("%q is signed with %s, which is not accepted", c.Subject.CommonName, c.SignatureAlgorithm)
		}
	}
	if roots == nil {
		if roots, err = x509.SystemCertPool(); err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
	} else {
		roots = roots.Clone()
	}
	inter := x509.NewCertPool()
	for _, c := range kp.Chain[1:] {
		if c.IsCA && c.CheckSignatureFrom(c) == nil {
			roots.AddCert(c)
		} else {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return kp, invalid("the chain cannot be verified: %v (include the intermediate certificates, and the root of an own CA)", err)
	}
	return kp, nil
}
