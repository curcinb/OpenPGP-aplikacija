package etf.openpgp.cb160549;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class Potpisivac {
	private final static int BUFFER_SIZE = 1 << 16;

	/**
	 * @param plainText Text koji treba da se potpise
	 * @param enckey Tajni kljuc za potpisivanje
	 * @param pass Lozinka pod kojom se cuva tajni kljuc
	 * @param zip Da li se koristi zip kompresija
	 * @param radix Da li se koristi radix64 konverzija
	 * @return Potpisana poruka
	 * @throws Exception
	 */
	public static String signText(String plainText, PGPSecretKey enckey, char[] pass, boolean zip, boolean radix)
			throws Exception {
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		ArmoredOutputStream armOut = new ArmoredOutputStream(bOut);

		ByteArrayInputStream bIn = new ByteArrayInputStream(plainText.getBytes("UTF8"));

		armOut.beginClearText(PGPUtil.SHA1);
		armOut.write(plainText.getBytes("UTF8"));
		armOut.write('\r');
		armOut.write('\n');
		armOut.endClearText();
		signFile(bIn, armOut, enckey, pass, true);
		armOut.close();

		return new String(bOut.toByteArray(), "UTF8");
	}

	/**
	 * @param in InputStream fajla koji se potpisuje
	 * @param out OutputStream u koji ce se upisati potipisana poruka
	 * @param key Tajni kljuc za potpisivanje
	 * @param pass Lozinka pod kojom se cuva tajni kljuc
	 * @param textmode Tip poruke
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws PGPException
	 * @throws SignatureException
	 */
	public static void signFile(InputStream in, OutputStream out, PGPSecretKey key, char[] pass, boolean textmode)
			throws IOException, NoSuchAlgorithmException, NoSuchProviderException, PGPException, SignatureException {
		PGPPrivateKey priK = key.extractPrivateKey(pass, "BC");

		PGPSignatureGenerator sGen = new PGPSignatureGenerator(key.getPublicKey().getAlgorithm(), PGPUtil.SHA1, "BC");

		if (textmode)
			sGen.initSign(PGPSignature.CANONICAL_TEXT_DOCUMENT, priK);
		else
			sGen.initSign(PGPSignature.BINARY_DOCUMENT, priK);

		Iterator it = key.getPublicKey().getUserIDs();
		if (it.hasNext()) {
			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
			spGen.setSignerUserID(false, (String) it.next());
			sGen.setHashedSubpackets(spGen.generate());
		}

		BCPGOutputStream bOut = new BCPGOutputStream(out);

		int rSize = 0;
		byte[] buf = new byte[BUFFER_SIZE];

		while ((rSize = in.read(buf)) >= 0)
			sGen.update(buf, 0, rSize);

		PGPSignature sig = sGen.generate();
		sig.encode(bOut);

	}

}
