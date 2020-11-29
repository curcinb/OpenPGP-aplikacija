package etf.openpgp.cb160549;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

public class Verifikator {

	/**
	 * Pomocna metoda kojom se radi verifikacija poruke
	 * @param plainText Tekst potpisane poruke
	 * @return	Javni kljuc kojim je poruka verifikovana
	 * @throws Exception
	 */
	public static String verifyText(String plainText) throws Exception {
		Pattern regex = Pattern.compile(
				"-----BEGIN PGP SIGNED MESSAGE-----\\r?\\n.*?\\r?\\n\\r?\\n(.*)\\r?\\n(-----BEGIN PGP SIGNATURE-----\\r?\\n.*-----END PGP SIGNATURE-----)",
				Pattern.CANON_EQ | Pattern.DOTALL);
		Matcher regexMatcher = regex.matcher(plainText);
		if (regexMatcher.find()) {
			String dataText = regexMatcher.group(1);
			String signText = regexMatcher.group(2);

			System.out.println(dataText);
			System.out.println(signText);

			ByteArrayInputStream dataIn = new ByteArrayInputStream(dataText.getBytes("UTF8"));
			ByteArrayInputStream signIn = new ByteArrayInputStream(signText.getBytes("UTF8"));

			return verifyFile3(dataText, signIn);
		}
		throw new Exception("Cannot recognize input data");
	}

	/**
	 * Metoda kojom se radi verifikacija poruke
	 * @param in Tekst potpisane poruke
	 * @param keyIn Tekst potpisa poruke
	 * @return	Javni kljuc kojim je poruka verifikovana
	 * @throws Exception
	 */
	public static String verifyFile3(String in, InputStream keyIn) throws Exception {
		keyIn = PGPUtil.getDecoderStream(keyIn);

		PGPObjectFactory pgpFact = new PGPObjectFactory(keyIn);

		PGPSignatureList p1 = (PGPSignatureList) pgpFact.nextObject();

		PGPSignature ops = p1.get(0);

		int ch;

		// kljuc iz prstena kljuceva sa id istim kao signIn
		PGPPublicKey key = PrstenKljuceva.getPublicKeyByID(ops.getKeyID()); 

		ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);

		for (int i = 0; in.charAt(i) != '\r'; i++) {
			ops.update((byte) in.charAt(i));
		}

		if (ops.verify()) {
			return new PPGPPJavniKljuc(key).toString();
		} else {
			return null;
		}
	}
}
