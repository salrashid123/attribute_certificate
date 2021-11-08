### Creating Attribute Certificates with Java

Sample java application that will issue an [https://en.wikipedia.org/wiki/Authorization_certificate](https://en.wikipedia.org/wiki/Authorization_certificate).

- [RFC 5755 An Internet Attribute Certificate Profile for Authorization](https://datatracker.ietf.org/doc/html/rfc5755)

I didn't even know there was such a thing and probably wouldn't have for a long time (its just not that common)...The only reason i did recently was while trying to approximate `Trusted Platform Module (TPM) based Remote attestation`.   Within that, the `Platform Certificate` that is sent is not your regular x509 cert but an `Attribute Cert`.

For an explanation of what an attribute cert is, well, see the wikipedia above.

What this repo does is basically just uses the [bouncy castle](https://www.bouncycastle.org/java.html) java provider to issue, sign and verify a very basic `Attribute Certificate`.  It also uses NSA's [Platform Attribute Certificate Creator (paccor)](https://github.com/nsacyber/paccor)

So, why did i need an attribute cert again, for the TPM?.  Yes, part of the TPM flow could involve the Platform Certificate which is simply a signed cert that includes some attributes about the system itself.  Critically, it includes the TPM's `Endorsement Key (EK)` as an attribute.  What that allows a remote user to say is "ok, i trust that this platform since i trust that the manufacturer of this platform signed this.  I also trust that this specific TPM is on that device because the EK is included in that `Attribute Certificate`.

For more information, see:

[`2.1.5 Assertions Made by a Platform Certificate`](https://trustedcomputinggroup.org/wp-content/uploads/IWG_Platform_Certificate_Profile_v1p1_r19_pub_fixed.pdf)

```
3.2 Platform Certificate
This section contains the format for a Platform Certificate conforming to version 1.0 of this specification.
The Platform Certificate makes the assertions listed in section 2.1.6. This certificate format
adheres to RFC 5755 [11] and all requirements and limitations from that specification apply unless otherwise noted.
```

You can find a sample of the reference Platform Certificate here: `tpm_reference_platform_cert.pem`

Now, what does this sample do? not that much beyond the bouncycastle test cases...but what i intend to do is add on more attributes to make it as conformal to TPM specs described.

From there, you use it in the grpc Remote Attestation flows once go supports those formats

- [TPM Remote Attestation protocol using go-tpm and gRPC (push)](https://github.com/salrashid123/go_tpm_remote_attestation/tree/push)
- [TPM Remote Attestation protocol using go-tpm and gRPC (pull)](https://github.com/salrashid123/go_tpm_remote_attestation/tree/pull)

---

to use the baseline just use maven

```bash
mvn clean install exec:java -q
```

This will generate an empty attribute certificate for you.  Unfortunately, you have to manually encode attributes as the ASN.1 values...
which is miserable. 

What i actually wanted to do is parse a TPM attribute certificate using [go-attestation](https://pkg.go.dev/github.com/google/go-attestation@v0.3.2/attributecert)..  as mentioned, you need to do is construct a very specific format thats compatible with TPM specifications...thats where the NSA's repo comes into the picture


### Setup Platform Attribute Certificate Creator (paccor)

The following will setup paccor on a GCP VM with a TPM.  You do not need to have a system with a TPM  but we will demo issuing a singed attribute certificate for an EK Certificate from the same VM


```bash
gcloud compute instances create paccor-vm  \
   --zone=us-central1-a --machine-type=e2-medium --no-service-account --no-scopes \
   --image=debian-11-bullseye-v20211105 --image-project=debian-cloud  \
   --shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring

# on paccor-vm

# install tpm2_tools.  While installing tpm2_tools is NOT necessary to use paccor, we are going
# to issue the EKCertificate to sign from this same VM...to do that we will use tpm2_tools

sudo su -

apt-get update

apt -y install   autoconf-archive   libcmocka0   libcmocka-dev  \
   procps   iproute2  curl default-jdk build-essential   git   pkg-config \
   gcc   libtool   automake   libssl-dev   uthash-dev   autoconf zip \
   doxygen  libcurl4-openssl-dev dbus-x11 libglib2.0-dev libjson-c-dev acl  libtspi-dev jq wget


cd
git clone https://github.com/tpm2-software/tpm2-tss.git
  cd tpm2-tss
  ./bootstrap
  ./configure --with-udevrulesdir=/etc/udev/rules.d
  make -j$(nproc)
  make install
  udevadm control --reload-rules && sudo udevadm trigger
  ldconfig

cd
git clone https://github.com/tpm2-software/tpm2-tools.git
  cd tpm2-tools
  ./bootstrap
  ./configure
  make check
  make install

# check version of java
$ java --version
	openjdk 11.0.13 2021-10-19
	OpenJDK Runtime Environment (build 11.0.13+8-post-Debian-1)
	OpenJDK 64-Bit Server VM (build 11.0.13+8-post-Debian-1, mixed mode, sharing)

# install gradle
$ gradle --version
    Gradle 6.3

# install golang
wget https://golang.org/dl/go1.17.3.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.17.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# install paccor
# paccor uses an old version of tpm2_tools
# if you want to paccor automatic scripts, checkout the 3.2.0 release of tpm2_tools
cd
git clone https://github.com/nsacyber/paccor.git
cd paccor
gradle build -x test 
gradle installDist

# paccor signer should be available at
/root/paccor/build/install/paccor/bin/signer
```

Now issue an EKCert and Platform cert
```bash
cd
git clone https://github.com/salrashid123/attribute_certificate
cd attribute_certificate


# on a gcp ShieldedVM, the EKCertificate is saved in NV
# extract the certificate

tpm2_nvread -o ekcert.der 0x01c00002
openssl x509 -in ekcert.der -inform DER -outform PEM -out ekcert.pem
openssl x509 -in ekcert.pem -text

# openssl x509 -in ekcert.der -inform DER -outform PEM -out ekcert.pem
openssl x509 -in ekcert.pem -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:43:f2:f9:3e:d0:12:42:d6:86:88:fb:48:ba:7c:b9:9e:dd:50
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = California, L = Mountain View, O = Google LLC, OU = Cloud, CN = "tpm_ek_v1_cloud_host-signer-0-2021-10-12T04:22:11-07:00 K:1, 3:nbvaGZFLcuc:0:18"
        Validity
            Not Before: Nov  7 22:15:15 2021 GMT
            Not After : Oct 31 22:20:15 2051 GMT
```

Use paccor to issue a certificate.

The CA certificate and key are provided in this rep

```
CA:
- CA_crt.crt (pem)
- CA_key.pem
```

Now finally, issue the platform certificate:

```bash
/root/paccor/build/install/paccor/bin/signer --extensionsJsonFile paccor/extentions.json   \
  --componentJsonFile paccor/localhost-componentlist.json --policyRefJsonFile paccor/localhost-policyreference.json \
  --serialNumber 1919 --publicKeyCert CA_crt.pem  --privateKeyFile  CA_key.pem \
  --holderCertFile ekcert.pem --dateNotBefore 20211106 --dateNotAfter 20211206 \
  --file platform_cert.der
```


now, run the provided go sample which will parse the EKCert, display is serial number as well as the serial number embedded inside the platform certificate.

Note that the platform certificate has an attribute which describes the serial number of the EK cert (thereby linking them together)

```
cd go_verify
go run main.go 
  CA Cert SubjectKeyId: v+Ec8CJIj/w7z13Z7a6IcCHf3YY
  Cert Verified
  Holder SerialNumber 143f2f93ed01242d68688fb48ba7cb99edd50
  EK Cert SerialNumber: 0143f2f93ed01242d68688fb48ba7cb99edd50
```

```
openssl x509 -in ekcert.pem -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:43:f2:f9:3e:d0:12:42:d6:86:88:fb:48:ba:7c:b9:9e:dd:50
```

I should point out that attribute certs with openssl is still pending [OpenSSL issues/14648](https://github.com/openssl/openssl/issues/14648).

---

### Reference

- [Host Integrity at Runtime and Start-up (HIRS)](https://github.com/nsacyber/HIRS)
- [CA ScratchPad](https://github.com/salrashid123/ca_scratchpad)
- [TCG EK Credential Profile](https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf)

---