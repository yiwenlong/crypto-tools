package pem

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

func DecodeX509Certificate(pemCert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemCert)
	if block == nil || block.Type != TypeCertificate {
		return nil, errors.New("Failed decode pem format certificate.")
	}
	return x509.ParseCertificate(block.Bytes)
}

func EncodeX509Certificate(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: TypeCertificate, Bytes: cert.Raw})
}
