
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.X509Extensions;

import com.lowagie.text.pdf.PdfPKCS7.X509NameTokenizer;

public class IcpBrasilUtils {
	private static DERObjectIdentifier CNPJ = new DERObjectIdentifier("2.16.76.1.3.3");
	private static DERObjectIdentifier CPF = new DERObjectIdentifier("2.16.76.1.3.1");

	public IcpBrasilUtils() {
	}

	private String getCnpj(Map<DERObjectIdentifier, String> otherNames) throws IOException {
		String cnpj = "Não encontrado";
		cnpj = otherNames.get(IcpBrasilUtils.CNPJ);

		return cnpj;
	}

	private String getCpf(Map<DERObjectIdentifier, String> otherNames) throws IOException {
		String cpf = "Não encontrado";
		cpf = otherNames.get(IcpBrasilUtils.CPF).substring(8, 19);

		return cpf;
	}

	/**
	 * Faz o parse do CDP - CRL Distribution Points
	 * (http://tools.ietf.org/html/rfc5280#section-4.2.1.13)
	 * 
	 * <pre>
	 * id-ce-cRLDistributionPoints OBJECT IDENTIFIER ::=  { id-ce 31 }
	 * 
	 * CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
	 * 
	 * DistributionPoint ::= SEQUENCE {
	 *      distributionPoint       [0]     DistributionPointName OPTIONAL,
	 *      reasons                 [1]     ReasonFlags OPTIONAL,
	 *      cRLIssuer               [2]     GeneralNames OPTIONAL }
	 * 
	 * DistributionPointName ::= CHOICE {
	 *      fullName                [0]     GeneralNames,
	 *      nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
	 * 
	 * ReasonFlags ::= BIT STRING {
	 *      unused                  (0),
	 *      keyCompromise           (1),
	 *      cACompromise            (2),
	 *      affiliationChanged      (3),
	 *      superseded              (4),
	 *      cessationOfOperation    (5),
	 *      certificateHold         (6),
	 *      privilegeWithdrawn      (7),
	 *      aACompromise            (8) }
	 * </pre>
	 */

	public String getEnderecoLcr(X509Certificate eeCert) throws CertificateParsingException {
		try {
			byte[] extDP = eeCert.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());

			return getEnderecoLcrAsString(extDP);
		} catch (Exception ex) {
			throw new CertificateParsingException("Erro ao interpretar o certificado", ex);
		}
	}

	private String getEnderecoLcrAsString(byte[] ext) throws IOException {

		StringBuilder buf = new StringBuilder();
		DEROctetString crlDistPointsOctets = (DEROctetString) ASN1Object.fromByteArray(ext);
		ASN1Sequence crlDistPoints = (ASN1Sequence) ASN1Object.fromByteArray(crlDistPointsOctets
		        .getOctets());

		for (int i = 0; i < crlDistPoints.size(); i++) {
			ASN1Sequence distPoint = (ASN1Sequence) crlDistPoints.getObjectAt(i);
			for (int j = 0; j < distPoint.size(); j++) {
				ASN1TaggedObject distPointElem = (ASN1TaggedObject) distPoint.getObjectAt(j);
				if (distPointElem.getTagNo() == 0) {
					ASN1TaggedObject distPointName = (ASN1TaggedObject) distPointElem.getObject();
					if (distPointName.getTagNo() == 0) {
						ASN1Sequence namesSequence = ASN1Sequence.getInstance(distPointName, false);
						if (namesSequence.size() != 0) {
							DERTaggedObject taggedObject = (DERTaggedObject) namesSequence
							        .getObjectAt(0);
							ASN1OctetString oct = ASN1OctetString.getInstance(taggedObject, false);
							DERIA5String url = DERIA5String.getInstance(oct);
							buf.append(url.getString() + ";");
						}
					}
				}
			}
		}

		return buf.toString();
	}

	public String getEnderecos(X509Certificate eeCert, String id)
	        throws CertificateParsingException {
		try {
			byte[] extDP = eeCert.getExtensionValue(id);

			return getEnderecoLcrAsString(extDP);
		} catch (Exception ex) {
			//throw new CertificateParsingException("Erro ao interpretar o certificado", ex);
		}
		return "";
	}

	public String getEntidadeCertificadora(X500Principal assunto) {
		if (assunto != null) {
			X509NameTokenizer NameTokenizer = new X509NameTokenizer(assunto.toString());

			while (NameTokenizer.hasMoreTokens()) {
				String token = NameTokenizer.nextToken();
				if (token.startsWith("O=")) {
					return token.substring(2, token.length());
				}
			}
		}
		return "";
	}

	public String getInscricao(X509Certificate eeCert) throws IOException {
		String inscricao = "Não encontrado";
		Map<DERObjectIdentifier, String> otherNames = getOtherNames(eeCert);

		if (otherNames.containsKey(IcpBrasilUtils.CNPJ)) {
			inscricao = getCnpj(otherNames);
		} else if (otherNames.containsKey(IcpBrasilUtils.CPF)) {
			inscricao = getCpf(otherNames);
		}

		return inscricao;
	}

	public String getNome(X500Principal assunto) {
		if (assunto != null) {
			X509NameTokenizer NameTokenizer = new X509NameTokenizer(assunto.toString());

			while (NameTokenizer.hasMoreTokens()) {
				String token = NameTokenizer.nextToken();
				if (token.startsWith("CN=")) {
					return token.substring(3, token.length());
				}
			}
		}
		return "";
	}

	/**
	 * Parse do Subject Alternative Name, de acordo com a RFC 5280
	 * (http://tools.ietf.org/html/rfc5280#section-4.2.1.6)
	 * 
	 * <pre>
	 * id-ce-subjectAltName OBJECT IDENTIFIER ::=  { id-ce 17 }
	 * 
	 * SubjectAltName ::= GeneralNames
	 * 
	 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	 * 
	 * GeneralName ::= CHOICE {
	 *  otherName                       [0]     OtherName,
	 *  rfc822Name                      [1]     IA5String,
	 *  dNSName                         [2]     IA5String,
	 *  x400Address                     [3]     ORAddress,
	 *  directoryName                   [4]     Name,
	 *  ediPartyName                    [5]     EDIPartyName,
	 *  uniformResourceIdentifier       [6]     IA5String,
	 *  iPAddress                       [7]     OCTET STRING,
	 *  registeredID                    [8]     OBJECT IDENTIFIER }
	 * 
	 * OtherName ::= SEQUENCE {
	 *  type-id    OBJECT IDENTIFIER,
	 *  value      [0] EXPLICIT ANY DEFINED BY type-id }
	 * 
	 * EDIPartyName ::= SEQUENCE {
	 *  nameAssigner            [0]     DirectoryString OPTIONAL,
	 *  partyName               [1]     DirectoryString }
	 * </pre>
	 */

	private Map<DERObjectIdentifier, String> getOtherNames(X509Certificate eeCert)
	        throws IOException {
		Map<DERObjectIdentifier, String> otherNames = new HashMap<DERObjectIdentifier, String>();

		try {
			Collection<List<?>> elementos = eeCert.getSubjectAlternativeNames();
			Iterator<List<?>> it = elementos.iterator();

			while (it.hasNext()) {

				List<?> sanElement = it.next();
				int elementType = (Integer) sanElement.get(0);

				if (elementType == 0) // othername
				{
					byte[] sanData = (byte[]) sanElement.get(1);

					ElementoSan el = parseOtherName(sanData);

					otherNames.put(el.getOid(), el.getValor());
				}
			}
		} catch (CertificateParsingException e) {
		}

		return otherNames;
	}

	public String getPolicies(X509Certificate eeCert) throws CertificateParsingException {
		try {
			byte[] extPolicies = eeCert.getExtensionValue(X509Extensions.CertificatePolicies
			        .getId());

			return getPoliciesAsString(extPolicies);
		} catch (Exception ex) {
			throw new CertificateParsingException("Erro ao interpretar o certificado", ex);
		}
	}

	private String getPoliciesAsString(byte[] ext) throws IOException {
		DEROctetString policiesPointsOctets = (DEROctetString) ASN1Object.fromByteArray(ext);
		ASN1Sequence policiesPoints = (ASN1Sequence) ASN1Object.fromByteArray(policiesPointsOctets
		        .getOctets());
		String element = null;
		for (int i = 0; i < policiesPoints.size(); i++) {
			ASN1Sequence distPoint = (ASN1Sequence) policiesPoints.getObjectAt(i);
			for (int j = 0; j < distPoint.size();) {
				element = distPoint.getObjectAt(j).toString();
				break;
			}
		}

		return element;
	}

	public boolean isFinalCertificate(X509Certificate eeCert) throws CertificateParsingException {
		try {
			int x = eeCert.getBasicConstraints();
			return x < 0 ? false : true;
		} catch (Exception ex) {
			throw new CertificateParsingException("Erro ao interpretar o certificado", ex);
		}
	}

	private ElementoSan parseOtherName(byte[] otherName) {
		ASN1Sequence seq;

		try {
			seq = (ASN1Sequence) ASN1Object.fromByteArray(otherName);

			DERObjectIdentifier oid = (DERObjectIdentifier) seq.getObjectAt(0);

			DERTaggedObject valor = (DERTaggedObject) seq.getObjectAt(1);

			DERTaggedObject taggedObj = (DERTaggedObject) valor.getObject();

			DERObject obj = taggedObj.getObject();

			String conteudo = "";

			if (obj instanceof DEROctetString) {
				DEROctetString oct = (DEROctetString) obj;
				conteudo = new String(oct.getOctets());
			} else if (obj instanceof DERPrintableString) {
				DERPrintableString oct = (DERPrintableString) obj;
				conteudo = new String(oct.getOctets());
			} else if (obj instanceof DERUTF8String) {
				DERUTF8String oct = (DERUTF8String) obj;
				conteudo = oct.getString();
			}

			return new ElementoSan(oid, conteudo);

		} catch (IOException e) {
			return new ElementoSan(new DERObjectIdentifier("0.0.0.0"), "");
		}
	}

}