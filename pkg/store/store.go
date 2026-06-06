package store

import (
	"crypto/x509"
	"errors"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"time"
)

type Store interface {
	FetchUser(caServer string, userId string) (*Account, error)
	WriteUser(caServer string, account *Account) error
	FetchResource(symbolicDomainName string) (*Certificates, error)
	WriteResource(symbolicDomainName string, resource *Certificates) error
	Lock(id string, timeout time.Duration) (bool, error)
	Release(id string) error
}

var ErrNotFoundUser = errors.New("not found user")
var ErrNotFoundCertificate = errors.New("not found certificate resource")

type Certificates struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"cert_url"`
	CertStableURL     string `json:"cert_stable_url"`
	PrivateKey        []byte `json:"private_key"`
	Certificate       []byte `json:"certificate"`
	IssuerCertificate []byte `json:"issuer_certificate"`
	CSR               []byte `json:"csr"`
}

func NewStoreResource(certificateResource *certificate.Resource) *Certificates {
	domain := ""
	if len(certificateResource.Domains) > 0 {
		domain = certificateResource.Domains[0]
	}
	return &Certificates{
		Domain:            domain,
		CertURL:           certificateResource.CertURL,
		CertStableURL:     certificateResource.CertStableURL,
		PrivateKey:        certificateResource.PrivateKey,
		Certificate:       certificateResource.Certificate,
		IssuerCertificate: certificateResource.IssuerCertificate,
		CSR:               certificateResource.CSR,
	}
}

func (c *Certificates) ToCertificateResource() *certificate.Resource {
	return &certificate.Resource{
		Domains:           []string{c.Domain},
		CertURL:           c.CertURL,
		CertStableURL:     c.CertStableURL,
		PrivateKey:        c.PrivateKey,
		Certificate:       c.Certificate,
		IssuerCertificate: c.IssuerCertificate,
		CSR:               c.CSR,
	}
}

func (c *Certificates) ExtractCertificate() ([]*x509.Certificate, error) {
	return certcrypto.ParsePEMBundle(c.Certificate)
}
