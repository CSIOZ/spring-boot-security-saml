package pl.csioz.gov.login.decrypt;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import pl.csioz.gov.login.decrypt.exception.BasicSamlException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

public class SamlXMLUtil {

    public static String serialize(Document samlMessage) throws BasicSamlException {
        try {
            if (samlMessage == null) {

                throw new BasicSamlException("Parametr samlMessage jest null-em");
            }
            StringWriter writer = new StringWriter();
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.STANDALONE, "yes");
            transformer.transform(new DOMSource(samlMessage), new StreamResult(writer));
            return writer.toString();
        }
        catch (TransformerConfigurationException e) {
            throw new BasicSamlException("Błąd wewnętrzny przy tworzeniu transformaty xml", e);
        }
        catch (TransformerException e) {
            throw new BasicSamlException("Błąd podczas serializacji dokumentu xml", e);
        }
    }


    public static Document deserialize(String samlMessage) throws BasicSamlException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setExpandEntityReferences(false);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            DocumentBuilder db = factory.newDocumentBuilder();
            return db.parse(new InputSource(new StringReader(samlMessage)));
        }
        catch (ParserConfigurationException e) {
            throw new BasicSamlException("Błąd konfiguracji DocumentBuilderFactory podczas deserializacji: "+e.getMessage(), e);
        }
        catch (IOException e) {
            throw new BasicSamlException("Błąd IO podczas parsowania na dokument xml: "+e.getMessage(), e);
        }
        catch (Exception e) {
            throw new BasicSamlException("Błąd podczas parsowania na dokument xml: "+e.getMessage(), e.getCause());
        }
    }
}
