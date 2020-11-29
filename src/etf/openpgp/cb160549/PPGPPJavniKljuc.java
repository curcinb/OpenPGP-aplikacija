package etf.openpgp.cb160549;

import java.util.Iterator;
import org.bouncycastle.openpgp.PGPPublicKey;

public class PPGPPJavniKljuc {
	/**
	 * PGP javni kljuc
	 */
	PGPPublicKey base;

	/**
	 * Konstruktor
	 * @param iBase PGP javni kljuc
	 */
	public PPGPPJavniKljuc(PGPPublicKey iBase) {
		base = iBase;
	}

	/**
	 * Getter
	 * @return PGP javni kljuc
	 */
	public PGPPublicKey getPublicKey() {
		return base;
	}

	@Override
	public String toString() {
		StringBuilder outStr = new StringBuilder();
		Iterator iter = base.getUserIDs();

		outStr.append("[0x");
		outStr.append(Integer.toHexString((int) base.getKeyID()).toUpperCase());
		outStr.append("] ");

		while (iter.hasNext()) {
			outStr.append(iter.next().toString());
			outStr.append("; ");
		}

		return outStr.toString();
	}

}
