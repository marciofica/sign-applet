
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.swing.JOptionPane;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;

public class ProcessSign {

    private static final String URL_SOL_ACESSO = "/e-nota/solicitacaoacessosign.faces";
    private String aliasCert;
    private Certificate[] certificate;
    private KeyInfo keyInfo;
    private PrivateKey privateKey;

    public String assinaRps(String xml, String certificado, String senha, String tagAssinar,
            String tipoCertificado, String library, String tokenName, PrintWriter writter, KeyStore keyStore, X509Certificate x509Certificate)
            throws Exception {

        Document document = documentFactory(xml);
        XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
        ArrayList<Transform> transformList = signatureFactory(signatureFactory);

        writter.append("\r\n[" + getDate() + "] Verificando informações do certificado");
        loadCertificate(certificado, senha, x509Certificate, signatureFactory, tipoCertificado, keyStore);

        for (int i = 0; i < document.getDocumentElement().getElementsByTagName(tagAssinar)
                .getLength(); i++) {
            assinarRpsSign(signatureFactory, transformList, privateKey, keyInfo, document,
                    tagAssinar, i, writter);
        }
        writter.append("\r\n[" + getDate() + "] Assinatura feita com sucesso!");
        JOptionPane.showMessageDialog(null, "[" + getDate() + "] Assinatura feita com sucesso!\r\n",
                "Assinatura efetuada com sucesso.", JOptionPane.INFORMATION_MESSAGE);
        return outputXml(document);
    }

    public void sendPdf(String urlTmp, Object[] params, String certificado, String senha,
            String tipoCertificado, String library, String tokenName, PrintWriter writter,
            String msgSucesso, KeyStore ks, X509Certificate x509) throws Exception {
        writter.append("\r\n[" + getDate() + "] Realizando o download do documento");
        URL url = new URL(getUrlWithParameters(urlTmp, params));
        InputStream input = getPdfToSignture(url);
        PdfReader pdfReader = new PdfReader(input);
        //Monta a conexao com o Servlet para escrever o arquivo assinado digitalmente
        HttpURLConnection connectionPost = (HttpURLConnection) url.openConnection();
        OutputStream output = getPdfStream(connectionPost);
        writter.append("\r\n[" + getDate() + "] Iniciando o processos de assinatura do documento");
        //Assina PDF
        assinaPdf(pdfReader, output, certificado, senha, tipoCertificado, library, tokenName, writter, ks, x509);
        //Envia o PDF para o servidor
        writter.append("\r\n[" + getDate() + "] Enviando para o servidor o documento assinado");
        BufferedReader rd = new BufferedReader(new InputStreamReader(
                connectionPost.getInputStream()));

        String line;
        while ((line = rd.readLine()) != null) {
            System.out.println(line);
        }
        output.close();
        input.close();
        rd.close();
        input.close();
        writter.append("\r\n[" + getDate() + "] " + msgSucesso);
        JOptionPane.showMessageDialog(null, "[" + getDate() + "] " + msgSucesso,
                "Assinatura efetuada com sucesso.", JOptionPane.INFORMATION_MESSAGE);
    }

    private void assinaPdf(PdfReader pdfReader, OutputStream output, String certificado,
            String senha, String tipoCertificado, String library, String tokenName,
            PrintWriter writter, KeyStore ks, X509Certificate x509Certificate) throws Exception {
        PdfStamper stamper = PdfStamper.createSignature(pdfReader, output, '\0');
        PdfSignatureAppearance signAppearance = stamper.getSignatureAppearance();

        // Carrega o certificado
        loadCertificate(certificado, senha, x509Certificate, null, tipoCertificado, ks);

        // Faz a assinatura e seta as propriedades do PDF
        signAppearance.setCrypto(privateKey, certificate, null,
                PdfSignatureAppearance.WINCER_SIGNED);
        signAppearance.setReason(aliasCert);
        signAppearance.setLocation("Fly e-Nota");
        signAppearance.setSignDate(Calendar.getInstance());
        signAppearance.setCertificationLevel(1);
        stamper.close();
    }

    private void assinarRpsSign(XMLSignatureFactory fac, ArrayList<Transform> transformList,
            PrivateKey privateKey, KeyInfo ki, Document document, String tagAssinar, int index,
            PrintWriter writter) throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, MarshalException, XMLSignatureException {

        writter.append("\r\n[" + getDate() + "] Iniciou o processo de assinatura");

        NodeList elements = document.getElementsByTagName(tagAssinar);
        Element el = (Element) elements.item(index);
        String id = el.getAttribute("Id");

        Reference ref = fac.newReference("#" + id, fac.newDigestMethod(DigestMethod.SHA1, null),
                transformList, null, null);
        SignedInfo si = fac
                .newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                (C14NMethodParameterSpec) null), fac.newSignatureMethod(
                SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));
        XMLSignature signature = fac.newXMLSignature(si, ki);
        DOMSignContext dsc = new DOMSignContext(privateKey, document.getDocumentElement()
                .getElementsByTagName(tagAssinar).item(index));
        signature.sign(dsc);
    }

    private Document documentFactory(String xml) throws ParserConfigurationException, SAXException,
            IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document docs = builder.parse(new ByteArrayInputStream(xml.getBytes()));
        return docs;
    }

    private String getDate() {
        Date dataAtual = new Date();
        SimpleDateFormat spf = new SimpleDateFormat("dd/MM/yyyy hh:mm:ss");
        return spf.format(dataAtual);
    }

    private OutputStream getPdfStream(HttpURLConnection connectionPost) throws IOException {
        //Monta a conexao com o Servlet para escrever o arquivo assinado digitalmente
        connectionPost.setRequestProperty("Content-Type", "application/pdf");
        connectionPost.setDoOutput(true);
        connectionPost.connect();
        return connectionPost.getOutputStream();
    }

    private InputStream getPdfToSignture(URL url) throws IOException {
        HttpURLConnection connectionGet = (HttpURLConnection) url.openConnection();
        connectionGet.setRequestProperty("Request-Method", "GET");
        connectionGet.setDoInput(true);
        connectionGet.setDoOutput(false);
        connectionGet.connect();
        return connectionGet.getInputStream();
    }

    private String getUrlWithParameters(String urlTmp, Object[] params) {
        String parameter = "?p1=" + params[0] + "&p2=" + params[1] + "&p3=" + params[2] + "&p4="
                + params[3];
        String urlservLet = urlTmp + ProcessSign.URL_SOL_ACESSO + parameter;
        return urlservLet;
    }

    private void loadCertificate(String aliasOrFile, String senha, X509Certificate x509Certificate, XMLSignatureFactory signatureFactory, String tipoCertificado, KeyStore keyStore) throws FileNotFoundException, KeyStoreException, Exception {
        KeyStore.PrivateKeyEntry pkEntry = null;
        KeyStore ks = null;
        // Quando o tipo de certificado for A1
        if ("A1".equalsIgnoreCase(tipoCertificado)) {
            InputStream entrada = new FileInputStream(aliasOrFile);
            ks = KeyStore.getInstance("pkcs12");
            try {
                ks.load(entrada, senha.toCharArray());
            } catch (Exception e) {
                throw new Exception(
                        "Senha do certificado digital incorreta ou o certificado é inválido.");
            }
        } else {
            ks = keyStore;
        }

        Enumeration<String> aliasesEnum = ks.aliases();
        while (aliasesEnum.hasMoreElements()) {
            String alias = aliasesEnum.nextElement();
            if (ks.isKeyEntry(alias)) {
                pkEntry = (PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(
                        senha.toCharArray()));
                privateKey = pkEntry.getPrivateKey();
                certificate = ks.getCertificateChain(alias);
                aliasCert = alias;
                break;
            }
        }

        X509Certificate cert = (X509Certificate) pkEntry.getCertificate();

        if (signatureFactory != null) {
            KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
            List<X509Certificate> x509Content = new ArrayList<X509Certificate>();
            x509Content.add(cert);
            X509Data x509Data = keyInfoFactory.newX509Data(x509Content);
            keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
        }

    }

    private String outputXml(Document doc) throws TransformerException,
            UnsupportedEncodingException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
        String xml = os.toString();
        if (xml != null && !"".equals(xml)) {
            xml = xml.replaceAll("\\r\\n", "");
            xml = xml.replaceAll(" standalone=\"no\"", "");
        }
        return URLEncoder.encode(xml, "utf-8");
    }

    private ArrayList<Transform> signatureFactory(XMLSignatureFactory signatureFactory)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ArrayList<Transform> transformList = new ArrayList<Transform>();
        TransformParameterSpec tps = null;
        Transform envelopedTransform = signatureFactory.newTransform(Transform.ENVELOPED, tps);
        Transform c14NTransform = signatureFactory.newTransform(
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", tps);
        transformList.add(envelopedTransform);
        transformList.add(c14NTransform);
        return transformList;
    }
}