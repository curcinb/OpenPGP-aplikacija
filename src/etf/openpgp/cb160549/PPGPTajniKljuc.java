package etf.openpgp.cb160549;

import java.util.Iterator;
import org.bouncycastle.openpgp.PGPSecretKey;

public class PPGPTajniKljuc {
	
	/**
	 * Tajni kljuc
	 */
	PGPSecretKey base;

	public PPGPTajniKljuc(PGPSecretKey iBase) {
		base = iBase;
	}

	public PGPSecretKey getSecretKey() {
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
