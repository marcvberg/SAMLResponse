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
import javax.xml.namespace.QName;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.xml.security.c14n.Canonicalizer;
import org.joda.time.DateTime;

import org.opensaml.core.config.Configuration;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.*;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
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
			InitializationService.initialize();
			
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
			
			//setSignature(response, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA256, certManager.getSigningCredential(publicKeyLocation, privateKeyLocation));
			setSignature(assertion, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA256, certManager.getSigningCredential(publicKeyLocation, privateKeyLocation));
			
			
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			SerializeSupport.writeNode(element, baos);
		
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
		response.setID("_" + UUID.randomUUID().toString());
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
		X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
		
		String value = org.apache.xml.security.utils.Base64.encode(cred.getEntityCertificate().getEncoded());
		
		cert.setValue(value);
		data.getX509Certificates().add(cert);
		keyInfo.getX509Datas().add(data);
		signature.setKeyInfo(keyInfo);
		
		signableXMLObject.setSignature(signature);
		((SAMLObjectContentReference) signature.getContentReferences().get(0)).setDigestAlgorithm(digestAlgorithm);
		
		MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(signableXMLObject);
		
		marshaller.marshall(signableXMLObject);
		
		org.apache.xml.security.Init.init();
		List<Signature> lsig = new ArrayList<>();
		lsig.add(signature);
		Signer.signObjects(lsig);
		
		return signableXMLObject;
	}
	
	
	private Assertion createAssertion(final DateTime issueDate, Subject subject, Issuer issuer, AuthnStatement authnStatement, AttributeStatement attributeStatement) 
	{
		AssertionBuilder assertionBuilder = new AssertionBuilder();
		Assertion assertion = assertionBuilder.buildObject();
		assertion.setID("_" + UUID.randomUUID().toString());
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
		subjectConfirmationData.setNotOnOrAfter(currentDate.plusYears(2));
		subjectConfirmationData.setNotBefore(currentDate.minusYears(2));
		
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
		statusCode.setValue(StatusCode.SUCCESS);

		StatusBuilder statusBuilder = new StatusBuilder();
		Status status = statusBuilder.buildObject();
		status.setStatusCode(statusCode);

		return status;
	}
	
	protected static XMLObject buildXMLObject(QName objectQName) throws Exception
	{
		XMLObjectBuilder builder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(objectQName);
		if (builder == null) 
		{	throw new Exception("Unable to retrieve builder for object QName " + objectQName); }
		return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(), objectQName.getPrefix());
	}
}
