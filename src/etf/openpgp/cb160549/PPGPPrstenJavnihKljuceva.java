package etf.openpgp.cb160549;

import java.util.Iterator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

public class PPGPPrstenJavnihKljuceva {
	/**
	 * Prsten javnih kljuceva
	 */
	PGPPublicKeyRing base;

	/**
	 * Konsturktor
	 * @param iBase Prsten javnih kljuceva
	 */
	public PPGPPrstenJavnihKljuceva(PGPPublicKeyRing iBase) {
		base = iBase;
	}

	/**
	 * Getter
	 * @return Prsten javnih kljuceva
	 */
	public PGPPublicKeyRing getPublicKeyRing() {
		return base;
	}

	/**
	 * Dohvatanje master kljuca
	 * @return Master kljuceva
	 */
	public PGPPublicKey getMasterKey() {
		return base.getPublicKey();
	}

	/**
	 * Dohvatanje kljuca za enkripciju
	 * @return Kljuc za enkripciju
	 */
	public PGPPublicKey getEncryptionKey() {
		Iterator iter = base.getPublicKeys();
		PGPPublicKey encKey = null;
		while (iter.hasNext()) {
			PGPPublicKey k = (PGPPublicKey) iter.next();
			if (k.isEncryptionKey())
				encKey = k;
		}

		return encKey;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PPGPPrstenJavnihKljuceva))
			return false;
		else
			return ((PPGPPrstenJavnihKljuceva) obj).base.equals(base);

	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 97 * hash + (this.base != null ? this.base.hashCode() : 0);
		return hash;
	}

	@Override
	public String toString() {
		StringBuilder outStr = new StringBuilder();
		Iterator iter = getMasterKey().getUserIDs();

		outStr.append("[0x");
		outStr.append(Integer.toHexString((int) getMasterKey().getKeyID()).toUpperCase());
		outStr.append("] ");

		while (iter.hasNext()) {
			outStr.append(iter.next().toString());
			outStr.append("; ");
		}

		return outStr.toString();
	}

}
