package com.amway.integration.saml;

import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateEncodingException;
//import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;

import org.apache.xml.security.c14n.Canonicalizer;
import org.joda.time.DateTime;

import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyValue;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.util.XMLHelper;

import org.w3c.dom.Element;


public class SamlAssertionProducer 
{

	private String privateKeyLocation;
	private String publicKeyLocation;
	private String destination;
	private CertManager certManager = new CertManager();
	
	public Response createSAMLResponse(final String subjectId, final DateTime authenticationTime, final String credentialType, final HashMap<String, List<String>> attributes, String issuer, Integer samlAssertionDays) 
	{
		try
		{
			DefaultBootstrap.bootstrap();
			
			//Signature signatureResponse = createSignature();
			//Signature signatureAssert = createSignature();
			Status status = createStatus();
			Issuer responseIssuer = null;
			Issuer assertionIssuer = null;
			Subject subject = null;
			AttributeStatement attributeStatement = null;
			
			if(issuer != null) 
			{
				responseIssuer = createIssuer(issuer);
				assertionIssuer = createIssuer(issuer);
			}
			
			if(subjectId != null)
			{	subject = createSubject(subjectId, samlAssertionDays); }
			
			if(attributes != null && attributes.size() != 0) 
			{	attributeStatement = createAttributeStatement(attributes); }
			
			AuthnStatement authnStatement = createAuthnStatement(authenticationTime);
			
			Assertion assertion = createAssertion(new DateTime(), subject, assertionIssuer, authnStatement, attributeStatement);
			
			Response response = createResponse(new DateTime(), responseIssuer, status, assertion);
			
			ResponseMarshaller marshaller = new ResponseMarshaller();
			Element element = marshaller.marshall(response);
			
			setSignature(response, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA1, certManager.getSigningCredential(publicKeyLocation, privateKeyLocation));
			setSignature(response, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA1, certManager.getSigningCredential(publicKeyLocation, privateKeyLocation));
			
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			XMLHelper.writeNode(element, baos);
		
			return response;
			
		} catch (Throwable t) {
			t.printStackTrace();
			return null;
		}
	}

	public String getPrivateKeyLocation() {
		return privateKeyLocation;
	}

	public void setPrivateKeyLocation(String privateKeyLocation) {
		this.privateKeyLocation = privateKeyLocation;
	}

	public String getPublicKeyLocation() {
		return publicKeyLocation;
	}

	public void setPublicKeyLocation(String publicKeyLocation) {
		this.publicKeyLocation = publicKeyLocation;
	}
	
	public void setDestination(String destination)
	{	this.destination = destination; }
	

	
	private Response createResponse(final DateTime issueDate, Issuer issuer, Status status, Assertion assertion) {
		ResponseBuilder responseBuilder = new ResponseBuilder();
		Response response = responseBuilder.buildObject();
		if(destination != null)
		{	response.setDestination(destination); }
		response.setID(UUID.randomUUID().toString());
		response.setIssueInstant(issueDate);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setIssuer(issuer);
		response.setStatus(status);
		response.getAssertions().add(assertion);
		return response;
	}
	
	public SignableXMLObject setSignature(SignableXMLObject signableXMLObject, String signatureAlgorithm, String digestAlgorithm, X509Credential cred)
		throws Exception
	{
		Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSigningCredential(cred);
		signature.setSignatureAlgorithm(signatureAlgorithm);
		signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		
		KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
		X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
		org.opensaml.xml.signature.X509Certificate cert = (org.opensaml.xml.signature.X509Certificate) buildXMLObject(org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
		
		String value = org.apache.xml.security.utils.Base64.encode(cred.getEntityCertificate().getEncoded());
		
		cert.setValue(value);
		data.getX509Certificates().add(cert);
		keyInfo.getX509Datas().add(data);
		signature.setKeyInfo(keyInfo);
		
		signableXMLObject.setSignature(signature);
		((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm);
		
		List<Signature> signatureList = new ArrayList<Signature>();
		signatureList.add(signature);
		
		MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(signableXMLObject);
		
		marshaller.marshall(signableXMLObject);
		
		org.apache.xml.security.Init.init();
		Signer.signObjects(signatureList);
		
		return signableXMLObject;
	}
	
	
	private Assertion createAssertion(final DateTime issueDate, Subject subject, Issuer issuer, AuthnStatement authnStatement, AttributeStatement attributeStatement) 
	{
		AssertionBuilder assertionBuilder = new AssertionBuilder();
		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID(UUID.randomUUID().toString());
		assertion.setIssueInstant(issueDate);
		assertion.setSubject(subject);
		assertion.setIssuer(issuer);
		
		if (authnStatement != null)
		{	assertion.getAuthnStatements().add(authnStatement); }
		
		if (attributeStatement != null)
		{	assertion.getAttributeStatements().add(attributeStatement); }
		
		return assertion;
	}
	
	private Issuer createIssuer(final String issuerName) {
		// create Issuer object
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerName);	
		return issuer;
	}
	
	private Subject createSubject(final String subjectId, final Integer samlAssertionDays) {
		DateTime currentDate = new DateTime();
		if (samlAssertionDays != null)
			currentDate = currentDate.plusDays(samlAssertionDays);
		
		// create name element
		NameIDBuilder nameIdBuilder = new NameIDBuilder(); 
		NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(subjectId);
		nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
	
		SubjectConfirmationDataBuilder dataBuilder = new SubjectConfirmationDataBuilder();
		SubjectConfirmationData subjectConfirmationData = dataBuilder.buildObject();
		subjectConfirmationData.setNotOnOrAfter(currentDate.plusMinutes(5));
		subjectConfirmationData.setNotBefore(currentDate.minusMinutes(5));
		
		SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
		SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
		subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer");
		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
		
		// create subject element
		SubjectBuilder subjectBuilder = new SubjectBuilder();
		Subject subject = subjectBuilder.buildObject();
		subject.setNameID(nameId);
		subject.getSubjectConfirmations().add(subjectConfirmation);
		
		return subject;
	}
	
	private AuthnStatement createAuthnStatement(final DateTime issueDate) {
		// create authcontextclassref object
		AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef classRef = classRefBuilder.buildObject();
		classRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
		
		// create authcontext object
		AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
		AuthnContext authnContext = authContextBuilder.buildObject();
		authnContext.setAuthnContextClassRef(classRef);
		
		// create authenticationstatement object
		AuthnStatementBuilder authStatementBuilder = new AuthnStatementBuilder();
		AuthnStatement authnStatement = authStatementBuilder.buildObject();
		authnStatement.setAuthnInstant(issueDate);
		authnStatement.setAuthnContext(authnContext);
		
		return authnStatement;
	}
	
	private AttributeStatement createAttributeStatement(HashMap<String, List<String>> attributes) {
		// create authenticationstatement object
		AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
		AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
		
		AttributeBuilder attributeBuilder = new AttributeBuilder();
		if (attributes != null) {
			for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
				Attribute attribute = attributeBuilder.buildObject();
				attribute.setName(entry.getKey());
				
				for (String value : entry.getValue()) {
					XSStringBuilder stringBuilder = new XSStringBuilder();
					XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
					attributeValue.setValue(value);
					attribute.getAttributeValues().add(attributeValue);
				}
				
				attributeStatement.getAttributes().add(attribute);
			}
		}
		
		return attributeStatement;
	}

	private Status createStatus() {
		StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
		StatusCode statusCode = statusCodeBuilder.buildObject();
		statusCode.setValue(StatusCode.SUCCESS_URI);

		StatusBuilder statusBuilder = new StatusBuilder();
		Status status = statusBuilder.buildObject();
		status.setStatusCode(statusCode);

		return status;
	}
	
	
	private Signature createSignature() throws Throwable 
	{
		if(publicKeyLocation != null && privateKeyLocation != null) 
		{
			BasicX509Credential credential = (BasicX509Credential) certManager.getSigningCredential(publicKeyLocation, privateKeyLocation);
			SignatureBuilder builder = new SignatureBuilder();
			Signature signature = builder.buildObject();
			signature.setNoNamespaceSchemaLocation("http://www.w3.org/2000/09/xmldsig#");
			signature.setSigningCredential(credential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			
			KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
			X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
			java.security.cert.X509Certificate x509cert = credential.getEntityCertificate();
			//org.opensaml.xml.signature.X509Certificate cert = (org.opensaml.xml.signature.X509Certificate) buildXMLObject(org.opensaml.xml.signature.X509Certificate.DEFAULT_ELEMENT_NAME);
			X509CertificateBuilder x509CertificateBuilder = new X509CertificateBuilder();
			org.opensaml.xml.signature.X509Certificate cert = x509CertificateBuilder.buildObject("http://www.w3.org/2000/09/xmldsig#", "X509Certificate", "ds");
			String value = org.apache.xml.security.utils.Base64.encode(x509cert.getEncoded());
			cert.setValue(wrapAt(value, 64));
			data.getX509Certificates().add(cert);
			keyInfo.getX509Datas().add(data);
			
			signature.setKeyInfo(keyInfo);
			
			return signature;
		}
		
		return null;
	}
	
	protected static XMLObject buildXMLObject(QName objectQName) throws Exception
	{
		XMLObjectBuilder builder = Configuration.getBuilderFactory().getBuilder(objectQName);
		if (builder == null) 
		{	throw new Exception("Unable to retrieve builder for object QName " + objectQName); }
		return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
	}
	
	private String wrapAt(String input, int lineLength)
	{
		if(input == null)
		{	return null; }
		int maxPos = input.length();
		if(maxPos < lineLength)
		{	return input; }
		StringBuilder sb = new StringBuilder();
		int currPos = 0;
		while(currPos < maxPos)
		{
			int endPos = Math.min(currPos+lineLength, maxPos);
			if(currPos > 0)
			{	sb.append("\n"); }
			sb.append(input.substring(currPos, endPos));
			currPos = endPos;
		}
		return sb.toString();
	}
}
