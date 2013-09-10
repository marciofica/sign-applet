

import java.security.cert.X509Certificate;

public class Certificados {

	private X509Certificate certificado;
	private boolean checked;
	private String emitidoPara;
	private String emitidoPor;
	private String entidade;
	private String validoAte;

	public Certificados() {

	}

	public Certificados(X509Certificate certificado, String emitidoPara, String emitidoPor,
	        String entidade, String validoAte, boolean checked) {
		this.certificado = certificado;
		this.emitidoPara = emitidoPara;
		this.emitidoPor = emitidoPor;
		this.entidade = entidade;
		this.validoAte = validoAte;
		this.checked = checked;
	}

	public X509Certificate getCertificado() {
		return certificado;
	}

	public String getEmitidoPara() {
		return emitidoPara;
	}

	public String getEmitidoPor() {
		return emitidoPor;
	}

	public String getEntidade() {
		return entidade;
	}

	public String getValidoAte() {
		return validoAte;
	}

	public boolean isChecked() {
		return checked;
	}

	public void setCertificado(X509Certificate certificado) {
		this.certificado = certificado;
	}

	public void setChecked(boolean checked) {
		this.checked = checked;
	}

	public void setEmitidoPara(String emitidoPara) {
		this.emitidoPara = emitidoPara;
	}

	public void setEmitidoPor(String emitidoPor) {
		this.emitidoPor = emitidoPor;
	}

	public void setEntidade(String entidade) {
		this.entidade = entidade;
	}

	public void setValidoAte(String validoAte) {
		this.validoAte = validoAte;
	}

	@Override
	public String toString() {
		return "Emitido para: " + emitidoPara + " Emitido por: " + emitidoPor + " Entidade: "
		        + entidade + " Válido até: " + validoAte;
	}
}
