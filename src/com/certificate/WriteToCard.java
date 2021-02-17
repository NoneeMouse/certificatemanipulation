package com.certificate;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.xml.bind.DatatypeConverter;

import com.certificate.CertificateDetails;
import com.certificate.CertificateUtil;
import com.certificate.Util;

public class WriteToCard {

	public static void main(String[] args) {
		// System.out.println("private key:"+util.loadKeys());
		try{
			// Show the list of all available card readers:
			TerminalFactory factory = TerminalFactory.getDefault();
			List<CardTerminal> terminals = factory.terminals().list();
			System.out.println("Reader: " + terminals);
			// Use the first card reader:

			CardTerminal terminal = getTerminal(terminals);
			// Establish a connection with the card:
			Card card = terminal.connect("*");
			System.out.println("Card: " + card);
			CardChannel channel = card.getBasicChannel();
			PersoService persoService=new PersoService(channel);
			byte aid[]={(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x63,(byte)0x50,(byte)0x4B,(byte)0x43,(byte)0x53,(byte)0x2D,(byte)0x31,(byte)0x35};

			System.out.println("Select Applet");
			persoService.selectApplet(aid);

			System.out.println("Set Applet state to initialization state(1)");
			persoService.setState((byte)1);

			System.out.println("Create file Structure in applet");
			persoService.createFileStructure();

			persoService.createFile(0x4101, 32767, false);

			persoService.selectFile((short)0x4101);

			byte[] certificate=null;
			CertificateDetails certDetails = CertificateUtil.getCertificateDetails("F:\\testing\\rki-ssl.p12", "girmiti01");
			try {
				certificate=certDetails.getX509Certificate().getEncoded();
				System.out.println("Encoded Certificate:");
				System.out.println(Util.byteArrayToString(certificate, false));
			} catch (CertificateEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			persoService.writeToFile(0x4101, certificate, false);


			persoService.createFile(0x4102, 32767, false);

			persoService.selectFile((short)0x4102);

			byte[] privatekey=certDetails.getPrivateKey().getEncoded();
			System.out.println("Encoded private key:");
			System.out.println(Util.byteArrayToString(privatekey,false));

			persoService.writeToFile(0x4102, privatekey, false);


			byte[] publickey=certDetails.getPublicKey().getEncoded();
			System.out.println("Encoded public key:");
			System.out.println(Util.byteArrayToString(publickey,false));
			persoService.createFile(0x4103, 32767, false);

			persoService.selectFile((short)0x4103);

			persoService.writeToFile(0x4103, publickey, false);

			persoService.setState((byte)3);


			System.out.println("read certificare from applet");
			byte[] cerdata = persoService.readFile((short)0x4101);

			String hexStr = Util.byteArrayToString(cerdata, false);
			System.out.println("File data information: "+hexStr);


			System.out.println("read private from applet");
			byte[] prikey = persoService.readFile((short)0x4102);

			hexStr = Util.byteArrayToString(prikey, false);
			System.out.println("File data information: "+hexStr);

			System.out.println("read public from applet");
			byte[] pubkey = persoService.readFile((short)0x4103);

			hexStr = Util.byteArrayToString(pubkey, false);
			System.out.println("File data information: "+hexStr);
			
			
			CertificateFactory certFactory=null;
	 		try {
	 			certFactory = CertificateFactory.getInstance("X.509");
	 		} catch (CertificateException e) {
	 			// TODO Auto-generated catch block
	 			e.printStackTrace();
	 		}
	 		InputStream in = new ByteArrayInputStream(cerdata);

	 		try {
	 			X509Certificate certcreated = (X509Certificate)certFactory.generateCertificate(in);
	 			
	 			X509EncodedKeySpec spec = new X509EncodedKeySpec(pubkey);
	 			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	 			PublicKey publicKey = keyFactory.generatePublic(spec);
	 			

	 			PKCS8EncodedKeySpec spec1 = new PKCS8EncodedKeySpec(prikey);
	 			KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
	 			PrivateKey privateKey = keyFactory.generatePrivate(spec1);
	 			
	 			X509Certificate certFromJksFile = certDetails.getX509Certificate();
	 			
	 			PublicKey jkspublickey = certDetails.getPublicKey();
	 			
	 			PrivateKey jksprivatekey = certDetails.getPrivateKey();
	 			
	 			if(certcreated.equals(certFromJksFile)) {
	 				System.out.println("certificate read from card & jks file are same");
	 			}
	 			if(publicKey.equals(jkspublickey)) {
	 				System.out.println("public key read from card & jks file are same");
	 			}
	 			if(privateKey.equals(jksprivatekey)) {
	 				System.out.println("private key read from card & jks file are same");
	 			}

	 		} catch (CertificateException e) {
	 			// TODO Auto-generated catch block
	 			e.printStackTrace();
	 		}

			/*			File file1 = new File("F:/testing/rki-ssl.p12");

			Pkcs12Util util = new Pkcs12Util(file1, "girmiti01");

			X509Certificate cert = util.getCertificate();

			System.out.println("Set certificate in applet");
			persoService.setCertificate(0x4101,cert,false);

			System.out.println("Set state of the applet to personalized state(3)");
			persoService.setState((byte)3);

			System.out.println("read file from applet");
			byte[] data = persoService.readFile((short)0x4101);

			 String hexStr = Util.byteArrayToString(data, false);
	         System.out.println("File data information: "+hexStr);

	         System.out.println("hex string of certificate:\n"+hexStr);
	 		CertificateFactory certFactory=null;
	 		try {
	 			certFactory = CertificateFactory.getInstance("X.509");
	 		} catch (CertificateException e) {
	 			// TODO Auto-generated catch block
	 			e.printStackTrace();
	 		}
	 		InputStream in = new ByteArrayInputStream(data);

	 		try {
	 			X509Certificate certcreated = (X509Certificate)certFactory.generateCertificate(in);
	 			util.certificateequal(certcreated);
	 		} catch (CertificateException e) {
	 			// TODO Auto-generated catch block
	 			e.printStackTrace();
	 		}
			 */
			// disconnect card:
			card.disconnect(false);

		}
		catch(Exception ex){

		}
	}

	private static CardTerminal getTerminal(List<CardTerminal> terminals) {
		for(CardTerminal ter:terminals){
			if(ter.getName().equalsIgnoreCase("Virtual Smart Card Architecture Virtual PCD 0")){
				return ter;
			}
		}
		return null;
	}

}
