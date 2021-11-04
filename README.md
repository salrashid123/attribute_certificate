### Creating Attribute Certificates with Java

Sample java application that will issue an [https://en.wikipedia.org/wiki/Authorization_certificate](https://en.wikipedia.org/wiki/Authorization_certificate).

- [RFC 5755 An Internet Attribute Certificate Profile for Authorization](https://datatracker.ietf.org/doc/html/rfc5755)

I didn't even know there was such a thing and probably wouldn't have for a long time (its just not that common)...The only reason i did recently was while trying to approximate `Trusted Platform Module (TPM) based Remote attestation`.   Within that, the `Platform Certificate` that is sent is not your regular x509 cert but an `Attribute Cert`.

For an explanation of what an attribute cert is, well, see the wikipedia above.

What this repo does is basically just uses the [bouncy castle](https://www.bouncycastle.org/java.html) java provider to issue, sign and verify a very basic `Attribute Certificate`.  Infact, its taken from their test cases [here](https://github.com/bcgit/bc-java/blob/master/misc/src/main/java/org/bouncycastle/jcajce/examples/AttrCertExample.java)

---

to run just use maven

```bash
mvn clean install exec:java -q
```


Note, i was originally trying to use openssl to issue the attribute cert but that work is still pending [OpenSSL issues/14648](https://github.com/openssl/openssl/issues/14648).


I also left a go sample code under `go_verify` which does not work yet.  I'll file a bug with go to ask about parsing (related, i think [golang/go/issues/47689](https://github.com/golang/go/issues/47689))

```
$ go run main.go 
CA Cert SubjectKeyId: v+Ec8CJIj/w7z13Z7a6IcCHf3YY
x509: inner and outer signature algorithm identifiers don't match
exit status 1
```

---

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

From there, use it in the grpc Remote Attestation flows once go supports those formats

- [TPM Remote Attestation protocol using go-tpm and gRPC (push)](https://github.com/salrashid123/go_tpm_remote_attestation/tree/push)
- [TPM Remote Attestation protocol using go-tpm and gRPC (pull)](https://github.com/salrashid123/go_tpm_remote_attestation/tree/pull)


Also see
[Host Integrity at Runtime and Start-up (HIRS)](https://github.com/nsacyber/HIRS)

which does infact use bouncycastle and constructs the AttributeCertificate's parameters here for a [PlatformCredential](https://github.com/nsacyber/HIRS/blob/master/HIRS_Utils/src/main/java/hirs/data/persist/certificate/PlatformCredential.java)


### Reference

- [CA ScratchPad](https://github.com/salrashid123/ca_scratchpad)
- [TCG EK Credential Profile](https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf)

---