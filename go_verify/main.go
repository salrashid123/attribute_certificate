package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-attestation/attributecert"
)

const (
	caCertFile = "../CA_crt.pem"
	ekCertFile = "../ekcert.pem"
	certFile   = "../platform_cert.der"
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
	certDER, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Println("Failed to decode PEM data.")
		os.Exit(1)
	}

	// read attribute certificate using
	// "github.com/google/go-attestation/attributecert"
	//   requires DER format
	// https://github.com/golang/go/issues/49270
	// derRaw, err := ioutil.ReadFile(certFile)
	// if err != nil {
	// 	fmt.Printf("failed to parse %s: %v", certFile, err)
	// 	os.Exit(1)
	// }

	// pcert, err := x509.ParseCertificate(derRaw)
	// if err != nil {
	// 	fmt.Printf("failed to parse %s: %v", certFile, err)
	// 	os.Exit(1)
	// }

	// fmt.Printf("%v", pcert)

	attributecert, err := attributecert.ParseAttributeCertificate(certDER)
	if err != nil {
		fmt.Printf("failed to parse %s: %v", certFile, err)
		os.Exit(1)
	}

	err = attributecert.CheckSignatureFrom(cacert)
	if err != nil {
		fmt.Printf("failed to verify signature on %s: %v", certFile, err)
		os.Exit(1)
	}
	fmt.Println("Cert Verified")

	fmt.Printf("Holder SerialNumber %s\n", fmt.Sprintf("%x", attributecert.Holder.Serial))

	er, _ := ioutil.ReadFile(ekCertFile)
	var eblock *pem.Block
	eblock, _ = pem.Decode(er)
	if block == nil {
		fmt.Println("Failed to decode PEM data.")
		os.Exit(1)
	}

	if eblock.Type != "CERTIFICATE" || len(eblock.Headers) != 0 {
		fmt.Println("Failed: Not a certificate.")
		os.Exit(1)
	}

	ecert, err := x509.ParseCertificate(eblock.Bytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("EK Cert SerialNumber: %s\n", hex.EncodeToString(ecert.SerialNumber.Bytes()))

}
