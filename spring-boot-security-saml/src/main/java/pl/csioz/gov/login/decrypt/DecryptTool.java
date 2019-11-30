package pl.csioz.gov.login.decrypt;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EllipticCurve;
import java.util.Base64;

@Slf4j
public class DecryptTool {

//	@Value("${decryption.ec.keystore.path}")
	private String decryptionEcKeystorePath = "/mykeys4";

//	@Value("${decryption.ec.keystore.pass}")
	private String decryptionEcKeystorePass = "123456";

//	@Value("${decryption.ec.keystore.keyalias}")
	private String decryptionEcKeystoreKeyAlias = "csioz_pr2dev_enc_ec";

	// Parametry deszyfracji odczytane z otrzymanego komunikatu

	// Identyfikator krzywej
	private String namedCurveOid;
	// Dane klucza publicznego efemerycznego nadawcy
	private byte[] publicKeyBytes;
	// Parametr KDF - algorithmID
	private String algorithmID;
	// Parametr KDF - partyUInfo, identyfikator nadawcy
	private String partyUInfo;
	// Parametr KDF - partyVInfo, identyfikator odbiorcy
	private String partyVInfo;
	// Identyfikator funkcji skrotu w operacji KDF
	private String digestMethodString;
	// Zaszyfrowany klucz
	private EncryptedKey ek;
	// Dokument
	private Document document;
	// Algorytm uzyty do zaszyfrowania klucza
	private String keyEncryptionMethod;

	public String decrypt(String encryptedXml) {
		try {

			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);

			// Załadowanie keystore z kluczem prywatnym wymaganym do odszyfrowania
			KeyStore keystore = KeyStore.getInstance("JKS");
			//File keys = ResourceUtils.getFile("classpath:mykeys4");
			keystore.load(this.getClass().getResourceAsStream(decryptionEcKeystorePath), decryptionEcKeystorePass.toCharArray());

			// Odczytanie klucza prywatnego
			Key privateKey = keystore.getKey(decryptionEcKeystoreKeyAlias, decryptionEcKeystorePass.toCharArray());

			log.info(String.format("Zaladowano keystore '%s' z kluczem prywatnym '%s' ", decryptionEcKeystorePath, decryptionEcKeystoreKeyAlias));

			// Deserializacja pliku do postaci 'Document'
			Document deserializedEncryptedAssertion = SamlXMLUtil.deserialize(encryptedXml);

			// Odczytanie istnotnych parametrow z odczytanego komunikatu ArtifactResponse (w szczegolnosci z elementu EncryptedAssertion)
			extractRequiredParameters(deserializedEncryptedAssertion);

			// Odtworzenie publicznego klucza efemerycznego z postaci przekazanej w zaszyfrowanej asercji
			// Procedura bazuje na paraemtrach odczytanych z danych od dostawcy tozsamosci 'OriginatorKeyInfo'
			ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(namedCurveOid);
			ECCurve curve = ecNamedCurveParameterSpec.getCurve();
			EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, ecNamedCurveParameterSpec.getSeed());
			java.security.spec.ECPoint ecPoint = ECPointUtil.decodePoint(ellipticCurve, publicKeyBytes);
			java.security.spec.ECParameterSpec ecParameterSpec = EC5Util.convertSpec(ellipticCurve, ecNamedCurveParameterSpec);
			java.security.spec.ECPublicKeySpec publicKeySpec = new java.security.spec.ECPublicKeySpec(ecPoint, ecParameterSpec);
			KeyFactory kf = KeyFactory.getInstance("EC", "SunEC");

			// klucz publiczny efemeryczny nadawcy
			ECPublicKey ecPublicKey = (ECPublicKey) kf.generatePublic(publicKeySpec);

			// Wykonanie operacji KeyAgreement
			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "SunEC");
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(ecPublicKey, true);

			// zrzucenie efektu key agreement do tablicy
			byte[] sharedSecret = keyAgreement.generateSecret();

			DigestMethod digestMethod = DigestMethod.fromURI(digestMethodString);

			// Wyznaczenie rozmiaru klucza do odwrappowania
			// metoda uproszczona majaca pokazac ogolny mechanizm
			int wrappedKeyArraySize = -1;
			if (keyEncryptionMethod.contains("kw-aes256")) {
				wrappedKeyArraySize = 256 / 8;
			} else if (keyEncryptionMethod.contains("kw-aes128")) {
				wrappedKeyArraySize = 128 / 8;
			} else if (keyEncryptionMethod.contains("kw-aes192")) {
				wrappedKeyArraySize = 192 / 8;
			}

			// wartosc wynika z zastosowanej dlugosci klucza w algorytmie KeyWrapping
			byte[] wrappedKeyBytes = new byte[wrappedKeyArraySize];

			// wykonanie funkcji KDF
			deriveKey(algorithmID, partyUInfo, partyVInfo, sharedSecret, wrappedKeyBytes, digestMethod, wrappedKeyArraySize);

			// Odtworzenie klucza AES na podsatwie wyniku operacji KDF
			SecretKeySpec wrapKey = new SecretKeySpec(wrappedKeyBytes, "AES");

			// odszyfrowanie klucza ktorym nadawca zaszyfrowal dane
			XMLCipher keyCipher = XMLCipher.getInstance();
			keyCipher.init(XMLCipher.UNWRAP_MODE, wrapKey);
			Key encryptionKey = keyCipher.decryptKey(ek, ek.getEncryptionMethod().getAlgorithm());

			// uzycie klucza uzyskanego powyzej do odszyfrowania danych (asercji)
			XMLCipher mainCipher = XMLCipher.getInstance();
			mainCipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);
			Document decryptedDoc = mainCipher.doFinal(document, document.getDocumentElement());

			String assertionAsString = SamlXMLUtil.serialize(decryptedDoc);

			log.info("Odszyfrowana asercja: " + assertionAsString);
			return assertionAsString;


		} catch (Exception e) {
			log.error(e.getMessage(), e);

		}
		return null;
	}

	/**
	 * Metoda odczytuje z zaladowanego dokumentu ArtifactResponse wszystkie potrzebne paraemtry
	 * Sposob dzialania jest dosc uproszczony i prymitywny, ma jedynie na celu pokazanie gdzie czego szukac
	 * Wyodrebniane wartosci o znaczeniu dla procesu deszyfracji to:
	 * OriginatorKeyInfo [publicKeyBytes, namedCurveOid] , ConcatKDFParams [algorithmID, partyUInfo, partyVInfo, digestMethodString], ek, document, keyEncryptionMethod
	 * @param deserializedEncryptedAssertion
	 * @throws Exception
	 */
	private void extractRequiredParameters(Document deserializedEncryptedAssertion) throws Exception {
		NodeList nlList = deserializedEncryptedAssertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion");

		Element encrypted = (Element) nlList.item(0);
		document = encrypted.getOwnerDocument();

		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);

		EncryptedData encryptedData = xmlCipher.loadEncryptedData(document, encrypted);
		ek = encryptedData.getKeyInfo().itemEncryptedKey(0);
		keyEncryptionMethod = ek.getEncryptionMethod().getAlgorithm();

		NodeList nlListAgreementMethod = ek.getKeyInfo().getElement().getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "AgreementMethod");
		Element agreementMethod = (Element) nlListAgreementMethod.item(0);

		NodeList nlListOriginatorKeyInfo = agreementMethod.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "OriginatorKeyInfo");
		Element originatorKeyInfo = (Element) nlListOriginatorKeyInfo.item(0);

		NodeList nlListKeyDerivationMethod = agreementMethod.getElementsByTagNameNS("http://www.w3.org/2009/xmlenc11#", "KeyDerivationMethod");
		Element keyDerivationMethod = (Element) nlListKeyDerivationMethod.item(0);

		NodeList nlListECKeyValue = originatorKeyInfo.getElementsByTagNameNS("http://www.w3.org/2009/xmldsig11#", "ECKeyValue");
		Element eCKeyValue = (Element) nlListECKeyValue.item(0);

		NodeList nlListPublicKey = eCKeyValue.getElementsByTagNameNS("http://www.w3.org/2009/xmldsig11#", "PublicKey");
		Element publicKey = (Element) nlListPublicKey.item(0);

		publicKeyBytes = Base64.getDecoder().decode(publicKey.getFirstChild().getTextContent());

		NodeList nlListNamedCurve = eCKeyValue.getElementsByTagNameNS("http://www.w3.org/2009/xmldsig11#", "NamedCurve");
		Element namedCurve = (Element) nlListNamedCurve.item(0);
		namedCurveOid = namedCurve.getAttribute("URI").replaceAll("urn:oid:", "");

		NodeList nlListConcatKDFParams = keyDerivationMethod.getElementsByTagNameNS("http://www.w3.org/2009/xmlenc11#", "ConcatKDFParams");
		Element concatKDFParams = (Element) nlListConcatKDFParams.item(0);
		algorithmID = concatKDFParams.getAttribute("AlgorithmID");
		partyUInfo = concatKDFParams.getAttribute("PartyUInfo");
		partyVInfo = concatKDFParams.getAttribute("PartyVInfo");

		NodeList nlListDigestMethod = concatKDFParams.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "DigestMethod");
		Element digestMethod = (Element) nlListDigestMethod.item(0);
		digestMethodString = digestMethod.getAttribute("Algorithm");
	}

	private static void deriveKey(String algorithmID, String partyUinfo, String partyVinfo, byte[] sharedSecretBytes, byte[] wrappedKeyBytes, DigestMethod dm, int length) throws Exception {
		ConcatenationKDFGenerator ckdf = new ConcatenationKDFGenerator(dm.getDigest());

		final byte[] algid = Hex.decodeHex(algorithmID.toCharArray());
		final byte[] uinfo = Hex.decodeHex(partyUinfo.toCharArray());
		final byte[] vinfo = Hex.decodeHex(partyVinfo.toCharArray());

		// Nalezy miec na uwadze specyfinczna konstrukcje paraemtrow algorithmID, partyUinfo, partyVinfo
		// Czyli, ze zakodowana wartosc posiada na poczatku paraemtr okreslajacy dlugsc wlasciwych danych
		// Do operacji KDF nalezy uzyc calej postaci danych


		ckdf.init(new KDFParameters(sharedSecretBytes, concatenate(algid, uinfo, vinfo)));
		ckdf.generateBytes(wrappedKeyBytes, 0, length);
	}


	private static byte[] concatenate(byte[]... args) {
		int length = 0, pos = 0;
		for (byte[] arg : args) {
			length += arg.length;
		}
		byte[] result = new byte[length];
		for (byte[] arg : args) {
			System.arraycopy(arg, 0, result, pos, arg.length);
			pos += arg.length;
		}
		return result;
	}
}
