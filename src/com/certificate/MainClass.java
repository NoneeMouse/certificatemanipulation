package com.certificate;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.io.ByteArrayInputStream;

import javax.smartcardio.*;
import javax.xml.bind.DatatypeConverter;
public class MainClass{


	{count=1;}
	int count=3;
	public MainClass(int count){
		super();
		this.count=count;

	}
	 static int SELECTED_TECHNOLOGY_MAG = 02;
	 static   int SELECTED_TECHNOLOGY_CHIP = 20;
	 static int SELECTED_TECHNOLOGY_CL = 06;
	 static int SELECTED_TECHNOLOGY_FALLBACK = 05;
	 static int SELECTED_TECHNOLOGY_MANUAL = 03;
	 static int SELECTED_TECHNOLOG_NONE = 00;
	public static void main(String args[]){
		System.out.println(new DecimalFormat("00").format(SELECTED_TECHNOLOGY_CHIP));
		/*File file1 = new File("F:/testing/rki-ssl.p12");

		Pkcs12Util util = new Pkcs12Util(file1, "girmiti01");

		byte[] data=util.isValidCert();

		String hexString="";
		for(int i=0;i<data.length;i++){
			hexString=hexString+(String.format("%02x",data[i]));
		}

		System.out.println("hex string of certificate:\n"+hexString);
		CertificateFactory certFactory=null;
		try {
			certFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		InputStream in = new ByteArrayInputStream(data);

		try {
			X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
			util.certificateequal(cert);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}



		//System.out.println("Is certificate valid : " + util.isValidCert());
		System.out.println("Issuer details : " + util.getIssuerName());
		System.out.println("Full details : " + util.getDetails());
		*/
	}
}
