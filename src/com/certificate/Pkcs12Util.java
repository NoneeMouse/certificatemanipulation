package com.certificate;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Objects;
import java.io.ByteArrayInputStream;

import javax.security.auth.x500.X500Principal;
public class Pkcs12Util {
	private File certificate;
	private String password;
	private KeyStore keyStore;

	public Pkcs12Util(String certPath, String password) {
		this(new File(certPath), password);
	}

	public Pkcs12Util(File certificate, String password) {
		Objects.nonNull(certificate);
		Objects.nonNull(password);

		this.certificate = certificate;
		this.password = password;
		init();
	}

	private void init() {
		try {
			keyStore = KeyStore.getInstance("pkcs12");
			keyStore.load(new FileInputStream(certificate),
					password.toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public X509Certificate getCertificate() {
		byte[] data=null;
		X509Certificate cer=null;
		try {
			Enumeration<String> e = keyStore.aliases();
			while (e.hasMoreElements()) {
				String alias = e.nextElement();
				 cer = (X509Certificate) keyStore
						.getCertificate(alias);

			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return  cer;
	}
	/**
	 * @return true if the certificate is valid, false if certificate expired.
	 */
	public byte[] isValidCert() {
		byte[] data=null;
		try {
			Enumeration<String> e = keyStore.aliases();
			while (e.hasMoreElements()) {
				String alias = e.nextElement();
				X509Certificate certificate = (X509Certificate) keyStore
						.getCertificate(alias);
				try {
					
					 data=certificate.getEncoded();
					
					
					/*CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
					InputStream in = new ByteArrayInputStream(data);
					
					X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
					
					if(cert.equals(certificate)){
						System.out.println("both are same");
					}
					
					certificate.checkValidity();
					return true;*/
					
				} catch (Exception ex) {
					return null;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return data;
	}

	public String loadKeys(){
		KeyStore.ProtectionParameter protParam =
				new KeyStore.PasswordProtection(password.toCharArray());

		// get my private key
		KeyStore.PrivateKeyEntry pkEntry=null;
		try {
			pkEntry = (KeyStore.PrivateKeyEntry)
					keyStore.getEntry("privateKeyAlias", protParam);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableEntryException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return pkEntry.getPrivateKey().toString();

		//PrivateKey myPrivateKey = pkEntry.getPrivateKey();

		/*// save my secret key
			    javax.crypto.SecretKey mySecretKey;
			    KeyStore.SecretKeyEntry skEntry =
			        new KeyStore.SecretKeyEntry(mySecretKey);
			    keyStore.setEntry("secretKeyAlias", skEntry, protParam);

			    // store away the keystore
			    java.io.FileOutputStream fos = null;
			    try {
			        fos = new java.io.FileOutputStream("newKeyStoreName");
			        keyStore.store(fos, password);
			    } finally {
			        if (fos != null) {
			            fos.close();
			        }
			    }*/
	}

	/**
	 * @return Issuer name
	 */
	public String getIssuerName() {
		try {
			Enumeration<String> e = keyStore.aliases();
			while (e.hasMoreElements()) {
				String alias = e.nextElement();
				X509Certificate certificate = (X509Certificate) keyStore
						.getCertificate(alias);
				X500Principal issuer = certificate.getIssuerX500Principal();

				return issuer.getName();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}

	public String getDetails() {
		try {
			Enumeration<String> e = keyStore.aliases();
			while (e.hasMoreElements()) {
				String alias = e.nextElement();
				X509Certificate certificate = (X509Certificate) keyStore
						.getCertificate(alias);

				return certificate.toString();

			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "";
	}

	public void certificateequal(X509Certificate cert) {
		// TODO Auto-generated method stub
		if(cert.equals(certificate)){
			System.out.println("both are same");
		}
		
	}
}
