package snshttp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
)

var defaultPattern = `^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$`

// Cache the most recently seen certificate.
var certCache = make(map[string]*x509.Certificate)
var certCacheMutex = sync.RWMutex{}

type message interface {
	getSignatureVersion() string
	getSignature() string
	getSigningCertURL() string
	SigningString() string
}

type verifierOption struct {
	requireTLS bool
	certHost   string
}

func WithCustomVerifier(requireTLS bool, certHost string) Option {
	return &verifierOption{
		requireTLS: requireTLS,
		certHost:   certHost,
	}
}

func (opt *verifierOption) apply(handler *handler) {
	handler.verifier.requireTLS = opt.requireTLS

	if len(opt.certHost) > 0 {
		handler.verifier.certHostPattern = regexp.MustCompile(opt.certHost)
	}
}

type SignatureVerifier struct {
	requireTLS      bool
	certHostPattern *regexp.Regexp
}

func NewSignatureVerifier() *SignatureVerifier {
	return &SignatureVerifier{
		requireTLS:      true,
		certHostPattern: regexp.MustCompile(defaultPattern),
	}
}

func (sg *SignatureVerifier) getCertificate(signingCertURL string) (*x509.Certificate, error) {
	// Check for a cached certificate first.
	certCacheMutex.RLock()
	cert, hit := certCache[signingCertURL]
	certCacheMutex.RUnlock()
	if hit {
		return cert, nil
	}

	certCacheMutex.Lock()
	defer certCacheMutex.Unlock()

	// Fetch the certificate.
	resp, err := http.Get(signingCertURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	decodedPem, _ := pem.Decode(body)
	if decodedPem == nil {
		return nil, errors.New("the decoded PEM file was empty")
	}

	parsedCertificate, err := x509.ParseCertificate(decodedPem.Bytes)
	if err != nil {
		return nil, err
	}

	// Replace any previously-cached certificate.
	for k := range certCache {
		delete(certCache, k)
	}
	certCache[signingCertURL] = parsedCertificate

	return parsedCertificate, nil
}

// Verifies that the certificate URL is using https and corresponds to an
// Amazon AWS domain.
func (sg *SignatureVerifier) verifyCertURL(signingCertURL string) error {
	certURL, err := url.Parse(signingCertURL)
	if err != nil {
		return err
	}

	if sg.requireTLS && certURL.Scheme != "https" {
		return errors.New("certificate URL is not using https")
	}
	if !sg.certHostPattern.Match([]byte(certURL.Host)) {
		return errors.New("certificate is located on an invalid domain")
	}

	return nil
}

// Verifies that a payload came from SNS.
func (sg *SignatureVerifier) Verify(m message) error {
	version := m.getSignatureVersion()
	if version != "1" {
		return fmt.Errorf("unsupported signature version %q", version)
	}

	signingCertURL := m.getSigningCertURL()
	if err := sg.verifyCertURL(signingCertURL); err != nil {
		return err
	}

	payloadSignature, err := base64.StdEncoding.DecodeString(m.getSignature())
	if err != nil {
		return err
	}

	cert, err := sg.getCertificate(signingCertURL)
	if err != nil {
		return err
	}

	return cert.CheckSignature(
		x509.SHA1WithRSA, []byte(m.SigningString()), payloadSignature)
}
