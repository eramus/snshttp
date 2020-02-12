package snshttp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sync"
)

var hostPattern = regexp.MustCompile(`^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$`)

// Cache the most recently seen certificate.
var certCache = make(map[string]*x509.Certificate)
var certCacheMutex = sync.RWMutex{}

type message interface {
	getSignatureVersion() string
	getSignature() string
	getSigningCertURL() string
	SigningString() string
}

func getCertificate(signingCertURL string) (*x509.Certificate, error) {
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

	body, err := ioutil.ReadAll(resp.Body)
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
func verifyCertURL(signingCertURL string) error {
	certURL, err := url.Parse(signingCertURL)
	if err != nil {
		return err
	}

	if certURL.Scheme != "https" {
		return errors.New("certificate URL is not using https")
	}
	if !hostPattern.Match([]byte(certURL.Host)) {
		return errors.New("certificate is located on an invalid domain")
	}

	return nil
}

// Verifies that a payload came from SNS.
func Verify(m message) error {
	version := m.getSignatureVersion()
	if version != "1" {
		return fmt.Errorf("unsupported signature version %q", version)
	}

	signingCertURL := m.getSigningCertURL()
	if err := verifyCertURL(signingCertURL); err != nil {
		return err
	}

	payloadSignature, err := base64.StdEncoding.DecodeString(m.getSignature())
	if err != nil {
		return err
	}

	cert, err := getCertificate(signingCertURL)
	if err != nil {
		return err
	}

	return cert.CheckSignature(
		x509.SHA1WithRSA, []byte(m.SigningString()), payloadSignature)
}
