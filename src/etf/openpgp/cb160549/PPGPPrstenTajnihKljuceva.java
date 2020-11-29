package etf.openpgp.cb160549;

import java.util.Iterator;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class PPGPPrstenTajnihKljuceva {
	
	/**
	 * Prsten tajnih kljuceva
	 */
	PGPSecretKeyRing base;

	/**
	 * Konstruktor
	 * @param iBase Prsten tajnih kljuceva
	 */
	public PPGPPrstenTajnihKljuceva(PGPSecretKeyRing iBase) {
		base = iBase;
	}

	/**
	 * Getter
	 * @return Prsten tajnih kljuceva
	 */
	public PGPSecretKeyRing getSecretKeyRing() {
		return base;
	}

	/**
	 * Dohvatanje master kljuca
	 * @return Tajni kljuc
	 */
	public PGPSecretKey getMasterKey() {
		return base.getSecretKey();
	}

	/**
	 * Dohvatanje kljuca za dekripciju
	 * @return Tajni kljuc
	 */
	public PGPSecretKey getDecryptionKey() {
		Iterator iter = base.getSecretKeys();
		while (iter.hasNext()) {
			PGPSecretKey k = (PGPSecretKey) iter.next();
			if (k.isMasterKey())
				return k;
		}
		return null;
	}

	/**
	 * Dohvatanje kljuca za potpisivanje
	 * @return Tajni kljuc
	 */
	public PGPSecretKey getSigningKey() {
		Iterator iter = base.getSecretKeys();
		while (iter.hasNext()) {
			PGPSecretKey k = (PGPSecretKey) iter.next();
			if (k.isSigningKey())
				return k;
		}
		return null;
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
