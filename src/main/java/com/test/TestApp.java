package com.test;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.RoleSyntax;
import org.bouncycastle.asn1.x509.X509AttributeIdentifiers;
import org.bouncycastle.cert.AttributeCertificateHolder;
import org.bouncycastle.cert.AttributeCertificateIssuer;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaAttributeCertificateIssuer;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.io.pem.PemReader;

public class TestApp {
	public static void main(String[] args) {
		TestApp tc = new TestApp();
	}

	public TestApp() {
		try {

			Security.addProvider(new BouncyCastleProvider());

			// https://github.com/bcgit/bc-java/blob/master/misc/src/main/java/org/bouncycastle/jcajce/examples/AttrCertExample.java#L180
			FileInputStream fis = new FileInputStream("CA_crt.pem");
			BufferedInputStream bis = new BufferedInputStream(fis);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate caCert = null;
			RSAPublicKey caPubKey = null;
			while (bis.available() > 0) {
				caCert = (X509Certificate) cf.generateCertificate(bis);
				// System.out.println(caCert.toString());
				caPubKey = (RSAPublicKey) caCert.getPublicKey();
			}

			X509Certificate clientCert = null;
			FileInputStream fis2 = new FileInputStream("client.crt");
			RSAPublicKey clientcaPubKey = null;
			BufferedInputStream bis2 = new BufferedInputStream(fis2);
			while (bis2.available() > 0) {
				clientCert = (X509Certificate) cf.generateCertificate(bis2);
				// System.out.println(clientCert.toString());
				clientcaPubKey = (RSAPublicKey) clientCert.getPublicKey();
			}

			PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream("CA_key.pem")));
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey caPrivKey = kf.generatePrivate(spec);
			pemReader.close();

			// Instantiate a new AC generator
			X509v2AttributeCertificateBuilder acBldr = new X509v2AttributeCertificateBuilder(
					new AttributeCertificateHolder(new JcaX509CertificateHolder(clientCert)),
					new JcaAttributeCertificateIssuer(caCert), new BigInteger("1"),
					new Date(System.currentTimeMillis() - 50000), // not before
					new Date(System.currentTimeMillis() + 50000)); // not after

			// the actual attributes

			GeneralName roleName = new GeneralName(GeneralName.uniformResourceIdentifier, "id://DAU123456789");

			acBldr.addAttribute(X509AttributeIdentifiers.id_at_role, new RoleSyntax(roleName));

			// finally create the AC
			X509AttributeCertificateHolder att = acBldr
					.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caPrivKey));

			// write it to a file
			System.out.println("Signature Algo: " + att.getSignatureAlgorithm().getAlgorithm());
			JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter("platform_cert.pem"));
			pemWriter.writeObject(att);
			pemWriter.flush();
			pemWriter.close();

			//
			// starting here, we parse the newly generated AC
			//

			// Holder
			AttributeCertificateHolder h = att.getHolder();
			if (h.match(clientCert)) {
				if (h.getEntityNames() != null) {
					System.out.println(h.getEntityNames().length + " entity names found");
				}
				if (h.getIssuer() != null) {
					System.out.println(
							h.getIssuer().length + " issuer names found, serial number " + h.getSerialNumber());
				}
				System.out.println("Matches original client x509 cert");
			}

			// Issuer
			AttributeCertificateIssuer issuer = att.getIssuer();
			if (issuer.match(caCert)) {
				if (issuer.getNames() != null) {
					System.out.println(issuer.getNames().length + " entity names found");
				}
				System.out.println("Matches original ca x509 cert");
			}

			// Dates
			System.out.println("valid not before: " + att.getNotBefore());
			System.out.println("valid not after: " + att.getNotAfter());

			// check the dates
			if (att.isValidOn(new Date())) {
				System.out.println("valid now");
			} else {
				System.out.println("cert is NOT valid now");
			}

			// verify
			if (att.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(caPubKey))) {
				System.out.println("signature valid now");
			} else {
				System.out.println("signature is NOT valid");
			}

			// Attribute
			Attribute[] attribs = att.getAttributes();
			System.out.println("cert has " + attribs.length + " attributes:");
			for (int i = 0; i < attribs.length; i++) {
				Attribute a = attribs[i];
				System.out.println("OID: " + a.getAttrType());
				// currently we only check for the presence of a 'RoleSyntax' attribute
				if (a.getAttrType().equals(X509AttributeIdentifiers.id_at_role)) {
					System.out.println("role syntax OID found in cert!");
				}
			}

		} catch (

		Exception ex) {
			System.out.println("Error:  " + ex);
		}
	}

}
