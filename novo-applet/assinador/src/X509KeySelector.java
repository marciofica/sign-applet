

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.Enumeration;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.*;

public class X509KeySelector extends KeySelector {

	private KeyStore ks;

	public X509KeySelector(KeyStore keyStore) throws KeyStoreException {
		if (keyStore == null) {
			throw new NullPointerException("keyStore is null");
		}
		ks = keyStore;
		ks.size();
	}

	@Override
	public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose,
	        AlgorithmMethod method, XMLCryptoContext context) throws KeySelectorException {

		SignatureMethod sm = (SignatureMethod) method;

		try {
			// return null if keyinfo is null or keystore is empty
			if (keyInfo == null || ks.size() == 0) {
				return new SimpleKeySelectorResult(null);
			}

			// Iterate through KeyInfo types
			Iterator i = keyInfo.getContent().iterator();
			while (i.hasNext()) {
				XMLStructure kiType = (XMLStructure) i.next();
				// check X509Data
				if (kiType instanceof X509Data) {
					X509Data xd = (X509Data) kiType;
					KeySelectorResult ksr = x509DataSelect(xd, sm);
					if (ksr != null) {
						return ksr;
					}
					// check KeyName
				} else if (kiType instanceof KeyName) {
					KeyName kn = (KeyName) kiType;
					Certificate cert = ks.getCertificate(kn.getName());
					if (cert != null
					        && algEquals(sm.getAlgorithm(), cert.getPublicKey().getAlgorithm())) {
						return new SimpleKeySelectorResult(cert.getPublicKey());
					}
					// check RetrievalMethod
				} else if (kiType instanceof RetrievalMethod) {
					RetrievalMethod rm = (RetrievalMethod) kiType;
					try {
						KeySelectorResult ksr = null;
						if (rm.getType().equals(X509Data.RAW_X509_CERTIFICATE_TYPE)) {
							OctetStreamData data = (OctetStreamData) rm.dereference(context);
							CertificateFactory cf = CertificateFactory.getInstance("X.509");
							X509Certificate cert = (X509Certificate) cf.generateCertificate(data
							        .getOctetStream());
							ksr = certSelect(cert, sm);
						} else if (rm.getType().equals(X509Data.TYPE)) {
							NodeSetData nd = (NodeSetData) rm.dereference(context);
							// convert nd to X509Data
							// ksr = x509DataSelect(xd, sm);
						} else {
							// skip; keyinfo type is not supported
							continue;
						}
						if (ksr != null) {
							return ksr;
						}
					} catch (Exception e) {
						throw new KeySelectorException(e);
					}
				}
			}
		} catch (KeyStoreException kse) {
			// throw exception if keystore is uninitialized
			throw new KeySelectorException(kse);
		}

		// return null since no match could be found
		return new SimpleKeySelectorResult(null);
	}

	private boolean algEquals(String algURI, String algName) {
		if (algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
			return true;
		} else if (algName.equalsIgnoreCase("RSA")
		        && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
			return true;
		} else {
			return false;
		}
	}

	private KeySelectorResult certSelect(X509Certificate xcert, SignatureMethod sm)
	        throws KeyStoreException {
		// skip non-signer certs
		boolean[] keyUsage = xcert.getKeyUsage();
		if (keyUsage[0] == false) {
			return null;
		}
		String alias = ks.getCertificateAlias(xcert);
		if (alias != null) {
			PublicKey pk = ks.getCertificate(alias).getPublicKey();
			// make sure algorithm is compatible with method
			if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
				return new SimpleKeySelectorResult(pk);
			}
		}
		return null;
	}

	private String getPKAlgorithmOID(String algURI) {
		if (algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) {
			return "1.2.840.10040.4.1";
		} else if (algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1)) {
			return "1.2.840.113549.1.1";
		} else {
			return null;
		}
	}

	private KeySelectorResult keyStoreSelect(CertSelector cs) throws KeyStoreException {
		Enumeration aliases = ks.aliases();
		while (aliases.hasMoreElements()) {
			String alias = (String) aliases.nextElement();
			Certificate cert = ks.getCertificate(alias);
			if (cert != null && cs.match(cert)) {
				return new SimpleKeySelectorResult(cert.getPublicKey());
			}
		}
		return null;
	}

	private KeySelectorResult x509DataSelect(X509Data xd, SignatureMethod sm)
	        throws KeyStoreException, KeySelectorException {

		// convert signature algorithm to compatible public-key alg OID
		String algOID = getPKAlgorithmOID(sm.getAlgorithm());

		KeySelectorResult ksr = null;
		Iterator xi = xd.getContent().iterator();
		while (xi.hasNext()) {
			ksr = null;
			Object o = xi.next();
			// check X509Certificate
			if (o instanceof X509Certificate) {
				X509Certificate xcert = (X509Certificate) o;
				ksr = certSelect(xcert, sm);
				// check X509IssuerSerial
			} else if (o instanceof X509IssuerSerial) {
				X509IssuerSerial xis = (X509IssuerSerial) o;
				X509CertSelector xcs = new X509CertSelector();
				try {
					xcs.setSubjectPublicKeyAlgID(algOID);
					xcs.setSerialNumber(xis.getSerialNumber());
					xcs.setIssuer(new X500Principal(xis.getIssuerName()).getName());
				} catch (IOException ioe) {
					throw new KeySelectorException(ioe);
				}
				ksr = keyStoreSelect(xcs);
				// check X509SubjectName
			} else if (o instanceof String) {
				String sn = (String) o;
				X509CertSelector xcs = new X509CertSelector();
				try {
					xcs.setSubjectPublicKeyAlgID(algOID);
					xcs.setSubject(new X500Principal(sn).getName());
				} catch (IOException ioe) {
					throw new KeySelectorException(ioe);
				}
				ksr = keyStoreSelect(xcs);
				// check X509SKI
			} else if (o instanceof byte[]) {
				byte[] ski = (byte[]) o;
				X509CertSelector xcs = new X509CertSelector();
				try {
					xcs.setSubjectPublicKeyAlgID(algOID);
				} catch (IOException ioe) {
					throw new KeySelectorException(ioe);
				}
				// DER-encode ski - required by X509CertSelector
				byte[] encodedSki = new byte[ski.length + 2];
				encodedSki[0] = 0x04; // OCTET STRING tag value
				encodedSki[1] = (byte) ski.length; // length
				System.arraycopy(ski, 0, encodedSki, 2, ski.length);
				xcs.setSubjectKeyIdentifier(encodedSki);
				ksr = keyStoreSelect(xcs);
				// check X509CRL
				// not supported: should use CertPath API
			} else {
				// skip all other entries
				continue;
			}
			if (ksr != null) {
				return ksr;
			}
		}
		return null;
	}

	private static class SimpleKeySelectorResult implements KeySelectorResult {
		private final Key key;

		SimpleKeySelectorResult(Key key) {
			this.key = key;
		}

		public Key getKey() {
			return key;
		}
	}
}