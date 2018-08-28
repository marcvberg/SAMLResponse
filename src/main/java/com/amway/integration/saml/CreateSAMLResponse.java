package com.amway.integration.saml;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;

import java.util.Base64;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ResponseMarshaller;
import org.w3c.dom.Element;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CreateSAMLResponse
{
	static public void main(String[] args) throws Exception
	{
		HashMap<String, List<String>> attributes = new HashMap<String, List<String>>();
		String issuer = "issuer";
		String subject = "subject";
		String privateKey = "private_key.pkcs12";
		String publicKey = "public_key.cer";
		Integer samlAssertionExpirationDays = 90;
		List<String> domain = Arrays.asList("api.amwayglobal.com");
		List<String> roles = Arrays.asList("login");
		List<String> email = Arrays.asList("andy.tomaszewski@amway.com");
		
		if(domain != null)
		{	attributes.put("domain", domain); }
		
		if(roles != null)
		{	attributes.put("roles", roles); }

		if(email != null)
		{	attributes.put("email", email); }

		SamlAssertionProducer producer = new SamlAssertionProducer();
		producer.setPrivateKeyLocation(privateKey);
		producer.setPublicKeyLocation(publicKey);
		producer.setDestination("https://api.amway.com/rest/v1/auth");
		Response responseInitial = producer.createSAMLResponse(subject, new DateTime(), "password", attributes, issuer, samlAssertionExpirationDays);
		
		ResponseMarshaller marshaller = new ResponseMarshaller();
		Element element = marshaller.marshall(responseInitial);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		SerializeSupport.writeNode(element, baos);
		String responseStr = new String(baos.toByteArray());
		try {
			BufferedWriter bf = new BufferedWriter(new FileWriter("output.saml"));
			bf.write(responseStr);
			bf.close();
		}
		catch(IOException e) {
			e.printStackTrace();
		}

		System.out.println(responseStr);
		Base64.Encoder encoder = Base64.getEncoder();
		System.out.println(encoder.encodeToString(responseStr.getBytes("utf-8")));
	}
	
}