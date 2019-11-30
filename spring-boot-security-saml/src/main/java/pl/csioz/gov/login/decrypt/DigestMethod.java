package pl.csioz.gov.login.decrypt;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

public enum DigestMethod {

    SHA_256("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256", 32),
    SHA_384("http://www.w3.org/2001/04/xmlenc#sha384", "SHA-384", 48),
    SHA_512("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512", 64);


    private final String uri;
    private final String name;
    private final Integer length;

    DigestMethod(String uri, String name, int len) {
        this.uri = uri;
        this.name = name;
        this.length = len;
    }

    public static DigestMethod fromURI(String uri) {
        for (DigestMethod e : values()) {
            if (e.uri.equals(uri))
                return e;
        }
        return null;
    }

    public String getAlgorithmURI() {
        return uri;
    }

    public int getLength() {
        return length;
    }

    public Digest getDigest() throws Exception {
        switch (this) {
            case SHA_256:
                return new SHA256Digest();
            case SHA_512:
                return new SHA512Digest();
            case SHA_384:
                return new SHA384Digest();
            default:
                throw new Exception("Nieznany algorytm skrutu");
        }
    }
}
