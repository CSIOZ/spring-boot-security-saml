//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.encoding.BaseSAML2MessageEncoder;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml2.ecp.RelayState;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.util.SOAPHelper;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransportUtils;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

public class HTTPPAOS11EncoderOld extends BaseSAML2MessageEncoder {
    private final Logger log = LoggerFactory.getLogger(HTTPSOAP11Encoder.class);

    public HTTPPAOS11EncoderOld() {
    }

    protected void doEncode(MessageContext messageContext) throws MessageEncodingException {
        if (!(messageContext instanceof SAMLMessageContext)) {
            this.log.error("Invalid message context type, this encoder only support SAMLMessageContext");
            throw new MessageEncodingException("Invalid message context type, this encoder only support SAMLMessageContext");
        } else if (!(messageContext.getOutboundMessageTransport() instanceof HTTPOutTransport)) {
            this.log.error("Invalid outbound message transport type, this encoder only support HTTPOutTransport");
            throw new MessageEncodingException("Invalid outbound message transport type, this encoder only support HTTPOutTransport");
        } else {
            SAMLMessageContext samlMsgCtx = (SAMLMessageContext)messageContext;
            SAMLObject samlMessage = samlMsgCtx.getOutboundSAMLMessage();
            if (samlMessage == null) {
                throw new MessageEncodingException("No outbound SAML message contained in message context");
            } else {
                if (samlMsgCtx.getRelayState() != null) {
                    SOAPHelper.addHeaderBlock(samlMsgCtx, this.getRelayState(samlMsgCtx.getRelayState()));
                }

                this.signMessage(samlMsgCtx);
                XMLObject outboundEnveloppe = samlMsgCtx.getOutboundMessage();
                Envelope envelope = this.buildPAOSMessage(samlMessage, outboundEnveloppe);
                Element envelopeElem = this.marshallMessage(envelope);

                try {
                    HTTPOutTransport outTransport = (HTTPOutTransport)messageContext.getOutboundMessageTransport();
                    HTTPTransportUtils.addNoCacheHeaders(outTransport);
                    HTTPTransportUtils.setUTF8Encoding(outTransport);
                    HTTPTransportUtils.setContentType(outTransport, "text/xml");
//                    outTransport.setHeader("SOAPAction", "http://www.oasis-open.org/committees/security");
                    Writer out = new OutputStreamWriter(outTransport.getOutgoingStream(), "UTF-8");
                    XMLHelper.writeNode(envelopeElem, out);
                    out.flush();
                } catch (UnsupportedEncodingException var9) {
                    this.log.error("JVM does not support required UTF-8 encoding");
                    throw new MessageEncodingException("JVM does not support required UTF-8 encoding");
                } catch (IOException var10) {
                    this.log.error("Unable to write message content to outbound stream", var10);
                    throw new MessageEncodingException("Unable to write message content to outbound stream", var10);
                }
            }
        }
    }

    protected RelayState getRelayState(String relayStateValue) {
        if (relayStateValue == null) {
            throw new IllegalArgumentException("RelayStateValue can't be null");
        } else if (relayStateValue.length() > 80) {
            throw new IllegalArgumentException("Relay state can't exceed size 80 when using ECP profile");
        } else {
            XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
            SAMLObjectBuilder<RelayState> relayStateBuilder = (SAMLObjectBuilder)builderFactory.getBuilder(RelayState.DEFAULT_ELEMENT_NAME);
            RelayState relayState = (RelayState)relayStateBuilder.buildObject();
            relayState.setSOAP11Actor("http://schemas.xmlsoap.org/soap/actor/next");
            relayState.setSOAP11MustUnderstand(true);
            relayState.setValue(relayStateValue);
            return relayState;
        }
    }

    protected Envelope buildPAOSMessage(SAMLObject samlMessage, XMLObject outboundEnvelope) {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        Envelope envelope;
        SOAPObjectBuilder bodyBuilder;
        if (outboundEnvelope != null && outboundEnvelope instanceof Envelope) {
            envelope = (Envelope)outboundEnvelope;
        } else {
            bodyBuilder = (SOAPObjectBuilder)builderFactory.getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
            envelope = (Envelope)bodyBuilder.buildObject();
        }

        bodyBuilder = (SOAPObjectBuilder)builderFactory.getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = (Body)bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(samlMessage);
        envelope.setBody(body);
        return envelope;
    }

    public String getBindingURI() {
        return "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";
    }

    public boolean providesMessageConfidentiality(MessageContext messageContext) throws MessageEncodingException {
        return messageContext.getOutboundMessageTransport().isConfidential();
    }

    public boolean providesMessageIntegrity(MessageContext messageContext) throws MessageEncodingException {
        return messageContext.getOutboundMessageTransport().isIntegrityProtected();
    }
}
