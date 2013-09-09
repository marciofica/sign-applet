


import org.bouncycastle.asn1.DERObjectIdentifier;

public class ElementoSan {
	private DERObjectIdentifier oid;
	private String valor;

	public ElementoSan(DERObjectIdentifier oid, String valor) {
		super();
		this.oid = oid;
		this.valor = valor;
	}

	public DERObjectIdentifier getOid() {
		return oid;
	}

	public String getValor() {
		return valor;
	}
}