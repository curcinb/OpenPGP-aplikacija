package etf.openpgp.cb160549;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;

public class Enkripter {
	private final static int BUFFER_SIZE = 1 << 16;

	/**
	 * Metoda koja vrsi enkripciju uz opciono potpisivanje i zipovanje/radix64
	 * konverziju
	 * 
	 * @param out
	 *            OutputStream enkriptovanog fajla
	 * @param fileName
	 *            Naziv fajla koji treba da se enkriptuje
	 * @param encKeys
	 *            Kolekcija javnih kkljuceva za enkripciju
	 * @param armor
	 *            Da li je radix64 konverzija omogucena
	 * @param signWithKey
	 *            Tajni kljuc za potpis poruke
	 * @param signKeyPass
	 *            Lozinka pod kojom se tajni kljuc cuva
	 * @param zip
	 *            Da li je zip kompresija omogucena
	 * @param algoritam
	 *            Simetricni algoritam za enkriptovanje
	 * @throws Exception
	 */
	public static void encryptFile(OutputStream out, String fileName, Collection<PGPPublicKey> encKeys, boolean armor,
			PGPSecretKey signWithKey, char[] signKeyPass, boolean zip, String algoritam) throws Exception {

		PGPSignatureGenerator signatureGenerator = null;
		if (armor)
			out = new ArmoredOutputStream(out);

		// Provera odabranog algoritma
		int algo = PGPEncryptedData.CAST5;

		if (algoritam == "CAST5")
			algo = PGPEncryptedData.CAST5;
		else
			algo = PGPEncryptedData.TRIPLE_DES;

		PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(algo, true, new SecureRandom(),
				"BC");

		for (PGPPublicKey encKey : encKeys)
			encryptedDataGenerator.addMethod(encKey);

		OutputStream compressedOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE]);

		// Inicijalizacija generatora za kompresiju
		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

		if (zip)
			compressedOut = compressedDataGenerator.open(compressedOut);

		// Ako imamo kljuc za potpis:
		if (signWithKey != null) {
			PGPPublicKey pubSigKey = signWithKey.getPublicKey();
			PGPPrivateKey secretKey = signWithKey.extractPrivateKey(signKeyPass, "BC");

			signatureGenerator = new PGPSignatureGenerator(pubSigKey.getAlgorithm(), PGPUtil.SHA1, "BC");
			signatureGenerator.initSign(PGPSignature.BINARY_DOCUMENT, secretKey);
			Iterator it = pubSigKey.getUserIDs();
			if (it.hasNext()) {
				PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
				spGen.setSignerUserID(false, (String) it.next());
				signatureGenerator.setHashedSubpackets(spGen.generate());
			}
			signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
		}

		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
		OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, fileName, new Date(),
				new byte[BUFFER_SIZE]);
		FileInputStream inputFileStream = new FileInputStream(fileName);
		byte[] buf = new byte[BUFFER_SIZE];
		int len;
		while ((len = inputFileStream.read(buf)) > 0) {
			literalOut.write(buf, 0, len);
			if (signatureGenerator != null)
				signatureGenerator.update(buf, 0, len);
		}

		literalOut.close();
		literalDataGenerator.close();
		if (signatureGenerator != null)
			signatureGenerator.generate().encode(compressedOut);

		compressedOut.close();
		compressedDataGenerator.close();
		encryptedDataGenerator.close();
		inputFileStream.close();
		out.close();

	}

}
