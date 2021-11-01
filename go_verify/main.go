package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	caCertFile = "../CA_crt.pem"
	certFile   = "../tpm_reference_platform_cert.pem"
)

func main() {

	// read signing ca cert
	r, _ := ioutil.ReadFile(caCertFile)
	var block *pem.Block
	block, _ = pem.Decode(r)
	if block == nil {
		fmt.Println("Failed to decode PEM data.")
		os.Exit(1)
	}

	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		fmt.Println("Failed: Not a certificate.")
		os.Exit(1)
	}

	cacert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("CA Cert SubjectKeyId: %s\n", base64.RawStdEncoding.EncodeToString(cacert.SubjectKeyId))

	// read attribute certificate
	certPEM, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Println("Failed to decode PEM data.")
		os.Exit(1)
	}
	block, _ = pem.Decode(certPEM)
	if block == nil {
		fmt.Println("Failed to decode PEM data.")
		os.Exit(1)
	}

	if block.Type != "ATTRIBUTE CERTIFICATE" || len(block.Headers) != 0 {
		fmt.Println("Failed: Not a certificate.")
		os.Exit(1)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Cert AuthorityKeyId: %s\n", base64.RawStdEncoding.EncodeToString(cert.AuthorityKeyId))

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(certPEM))
	if !ok {
		panic("failed to parse root certificate")
	}

	opts := x509.VerifyOptions{
		Roots: roots,
		//DNSName:       "server.esodemoapp2.com",
		Intermediates: x509.NewCertPool(),
	}

	if _, err := cert.Verify(opts); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Cert Verified")
}
