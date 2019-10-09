package com.github.ulisesbocchio.spring.boot.security.saml.configurer.builder;

import com.github.ulisesbocchio.spring.boot.security.saml.configurer.ServiceProviderBuilder;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLProcessorProperties;
import com.github.ulisesbocchio.spring.boot.security.saml.properties.SAMLSSOProperties;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.params.HttpClientParams;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.velocity.app.VelocityEngine;
import org.assertj.core.util.VisibleForTesting;
import org.opensaml.liberty.binding.decoding.HTTPPAOS11Decoder;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11DecoderImpl;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import pl.csioz.gov.login.encoder.HTTPPAOS11Encoder;
import pl.csioz.gov.login.encoder.HTTPSOAP11Encoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Builder configurer that takes care of configuring/customizing the {@link SAMLProcessor} bean.
 * <p>
 * Common strategy across most internal configurers is to first give priority to a Spring Bean if present in the
 * Context.
 * So if not {@link SAMLProcessor} bean is defined, priority goes to a custom SAMLProcessor provided explicitly
 * to this configurer through the constructor. And if not provided through the constructor, a default implementation is
 * instantiated that is configurable through the DSL methods.
 * </p>
 * <p>
 * This configurer also reads the values from {@link SAMLSSOProperties#getSamlProcessor()} if no custom SAMLProcessor
 * is provided, for some DSL methods if they are not used. In other words, the user is able to configure the
 * SAMLProcessor through the
 * following properties:
 * <pre>
 *     saml.sso.saml-processor.redirect
 *     saml.sso.saml-processor.post
 *     saml.sso.saml-processor.artifact
 *     saml.sso.saml-processor.soap
 *     saml.sso.saml-processor.paos
 * </pre>
 * </p>
 *
 * @author Ulises Bocchio
 */
public class SAMLProcessorConfigurer extends SecurityConfigurerAdapter<Void, ServiceProviderBuilder> {

    private static VelocityEngine velocityEngine;
    private SAMLProcessor sAMLProcessor;
    private SAMLProcessor sAMLProcessorBean;
    private Boolean redirect = null;
    private Boolean post = null;
    private Boolean artifact = null;
    private Boolean soap = null;
    private Boolean paos = null;

    private HTTPRedirectDeflateBinding redirectBinding;
    private HTTPPostBinding postBinding;
    private HTTPArtifactBinding artifactBinding;
    private HTTPSOAP11Binding soapBinding;
    private HTTPPAOS11Binding paosBinding;
    private SAMLProcessorProperties processorConfig;
    private ParserPool parserPool;

    public SAMLProcessorConfigurer(SAMLProcessor sAMLProcessor) {
        this.sAMLProcessor = sAMLProcessor;
    }

    public SAMLProcessorConfigurer() {

    }

    @Override
    public void init(ServiceProviderBuilder builder) throws Exception {
        sAMLProcessorBean = builder.getSharedObject(SAMLProcessor.class);
        processorConfig = builder.getSharedObject(SAMLSSOProperties.class).getSamlProcessor();
        parserPool = builder.getSharedObject(ParserPool.class);
    }

    @Override
    public void configure(ServiceProviderBuilder builder) throws Exception {
        if (sAMLProcessorBean == null) {
            if (sAMLProcessor == null) {
                List<SAMLBinding> bindings = new ArrayList<>();

                if (redirectBinding != null) {
                    bindings.add(redirectBinding);
                } else if (Optional.ofNullable(redirect).orElseGet(processorConfig::isRedirect)) {
                    bindings.add(postProcess(createDefaultRedirectBinding()));
                }

                if (postBinding != null) {
                    bindings.add(postBinding);
                } else if (Optional.ofNullable(post).orElseGet(processorConfig::isPost)) {
                    bindings.add(postProcess(createDefaultPostBinding()));
                }

                if (artifactBinding != null) {
                    bindings.add(artifactBinding);
                } else if (Optional.ofNullable(artifact).orElseGet(processorConfig::isArtifact)) {
                    bindings.add(postProcess(createDefaultArtifactBinding(builder)));
                }

                if (soapBinding != null) {
                    bindings.add(soapBinding);
                } else if (Optional.ofNullable(soap).orElseGet(processorConfig::isSoap)) {
                    bindings.add(postProcess(createDefaultSoapBinding()));
                }

                if (paosBinding != null) {
                    bindings.add(paosBinding);
                } else if (Optional.ofNullable(paos).orElseGet(processorConfig::isPaos)) {
                    bindings.add(postProcess(createDefaultPaosBinding()));
                }
                sAMLProcessor = createDefaultSamlProcessor(bindings);
            }

            builder.setSharedObject(SAMLProcessor.class, sAMLProcessor);
        }
    }

    @VisibleForTesting
    protected HTTPPAOS11Binding createDefaultPaosBinding() {
        return new HTTPPAOS11Binding(new HTTPPAOS11Decoder(parserPool), new HTTPPAOS11Encoder());
    }

    @VisibleForTesting
    protected HTTPSOAP11Binding createDefaultSoapBinding() {
        return new HTTPSOAP11Binding(new HTTPSOAP11DecoderImpl(parserPool), new HTTPSOAP11Encoder());
    }

    @VisibleForTesting
    protected HTTPArtifactBinding createDefaultArtifactBinding(ServiceProviderBuilder builder) {
        HttpClientParams params = new HttpClientParams();
        params.setIntParameter(HttpConnectionParams.CONNECTION_TIMEOUT, 60000);
        HttpClient httpClient = new HttpClient(params, new MultiThreadedHttpConnectionManager());
        ArtifactResolutionProfileImpl artifactResolutionProfile = new ArtifactResolutionProfileImpl(httpClient);
        builder.setSharedObject(ArtifactResolutionProfile.class, artifactResolutionProfile);
        HTTPSOAP11Encoder soapEncoder = new HTTPSOAP11Encoder();
        HTTPSOAP11Binding soapBinding = new HTTPSOAP11Binding(new HTTPSOAP11DecoderImpl(parserPool), soapEncoder);
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding));
        return new HTTPArtifactBinding(parserPool, getVelocityEngine(), artifactResolutionProfile);
    }

    @VisibleForTesting
    protected HTTPPostBinding createDefaultPostBinding() {
        return new HTTPPostBinding(parserPool, getVelocityEngine());
    }

    @VisibleForTesting
    protected HTTPRedirectDeflateBinding createDefaultRedirectBinding() {
        return new HTTPRedirectDeflateBinding(parserPool);
    }

    @VisibleForTesting
    protected SAMLProcessorImpl createDefaultSamlProcessor(List<SAMLBinding> bindings) {
        return new SAMLProcessorImpl(bindings);
    }

    private VelocityEngine getVelocityEngine() {
        if (velocityEngine == null) {
            velocityEngine = VelocityFactory.getEngine();
        }
        return velocityEngine;
    }

    /**
     * HTTP Redirect Bindings are enabled by default. Call this method if you want to disable Redirect Bindings.
     * Not relevant if using {@link #redirectBinding(HTTPRedirectDeflateBinding)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.saml-processor.redirect
     * </pre>
     * </p>
     *
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer disableRedirectBinding() {
        redirect = false;
        return this;
    }

    /**
     * Provide a specific {@link HTTPRedirectDeflateBinding} bindings. Overrides value set by {@link
     * #disableRedirectBinding()}
     *
     * @param binding the actual Redirect bindings
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer redirectBinding(HTTPRedirectDeflateBinding binding) {
        redirect = true;
        redirectBinding = binding;
        return this;
    }

    /**
     * HTTP Post Bindings are enabled by default. Call this method if you want to disable Post Bindings.
     * Not relevant if using {@link #postBinding(HTTPPostBinding)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.saml-processor.post
     * </pre>
     * </p>
     *
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer disablePostBinding() {
        post = false;
        return this;
    }

    /**
     * Provide a specific {@link HTTPPostBinding} bindings. Overrides value set by {@link #disablePostBinding()}
     *
     * @param binding the actual Post bindings
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer postBinding(HTTPPostBinding binding) {
        post = true;
        postBinding = binding;
        return this;
    }

    /**
     * HTTP Artifact Bindings are enabled by default. Call this method if you want to disable Artifact Bindings.
     * Not relevant if using {@link #artifactBinding(HTTPArtifactBinding)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.saml-processor.artifact
     * </pre>
     * </p>
     *
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer disableArtifactBinding() {
        artifact = false;
        return this;
    }

    /**
     * Provide a specific {@link HTTPArtifactBinding} bindings. Overrides value set by {@link
     * #disableArtifactBinding()}
     *
     * @param binding the actual Artifact bindings
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer artifactBinding(HTTPArtifactBinding binding) {
        artifact = true;
        artifactBinding = binding;
        return this;
    }

    /**
     * HTTP SOAP Bindings are enabled by default. Call this method if you want to disable SOAP Bindings.
     * Not relevant if using {@link #soapBinding(HTTPSOAP11Binding)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.saml-processor.soap
     * </pre>
     * </p>
     *
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer disableSoapBinding() {
        soap = false;
        return this;
    }

    /**
     * Provide a specific {@link HTTPSOAP11Binding} bindings. Overrides value set by {@link #disableSoapBinding()}
     *
     * @param binding the actual SOAP bindings
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer soapBinding(HTTPSOAP11Binding binding) {
        soap = true;
        soapBinding = binding;
        return this;
    }

    /**
     * HTTP PAOS Bindings are enabled by default. Call this method if you want to disable PAOS Bindings.
     * Not relevant if using {@link #paosBinding(HTTPPAOS11Binding)}.
     * <p>
     * Alternatively use property:
     * <pre>
     *      saml.sso.saml-processor.paos
     * </pre>
     * </p>
     *
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer disablePaosBinding() {
        paos = false;
        return this;
    }

    /**
     * Provide a specific {@link HTTPPAOS11Binding} bindings. Overrides value set by {@link #disablePaosBinding()}
     *
     * @param binding the actual PAOS bindings
     * @return this configurer for further customization
     */
    public SAMLProcessorConfigurer paosBinding(HTTPPAOS11Binding binding) {
        paos = true;
        paosBinding = binding;
        return this;
    }
}
