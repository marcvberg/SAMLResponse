package com.amway.integration.saml;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.util.XMLHelper;
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
		String subject = "subjkect";
		String privateKey = "servicecatalog-dv-privkey-20180103.pkcs12";
		String publicKey = "servicecatalog-dv-req-20180103.cer";
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
		
		Response responseInitial = producer.createSAMLResponse(subject, new DateTime(), "password", attributes, issuer, samlAssertionExpirationDays);
		
		ResponseMarshaller marshaller = new ResponseMarshaller();
		Element element = marshaller.marshall(responseInitial);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLHelper.writeNode(element, baos);
		String responseStr = new String(baos.toByteArray());
		
		System.out.println(responseStr);
	}
	
}