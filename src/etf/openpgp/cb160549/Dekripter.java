package etf.openpgp.cb160549;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;
import java.util.Iterator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;

public class Dekripter {

	/**
	 * Metoda koja dekriptuje fajl i vraca instancu klase RezultatDekripcije
	 * 
	 * @param in
	 *            Input stream fajla koji se dekriptuje
	 * @param passwd
	 *            Lozinka kojom je zasticen privatni kljuc koji odogvara javnom
	 *            kljucu kojim je poruka enkriptovana
	 * @param out
	 *            Output stream dekriptovanog fajla
	 * @return Instanca klase RezultatDekripcije
	 * @throws Exception
	 */
	public static RezultatDekripcije decryptFile(InputStream in, char[] passwd, OutputStream out) throws Exception {

		RezultatDekripcije decryptionRes = new RezultatDekripcije();
		String outFileName = "";
		PGPPublicKeyEncryptedData pbe = null;

		in = PGPUtil.getDecoderStream(in);

		PGPObjectFactory pgpF = new PGPObjectFactory(in);
		PGPEncryptedDataList enc;
		Object o = pgpF.nextObject();

		// Prvi objekat moze da bude PGP marker paket
		if (o instanceof PGPEncryptedDataList)
			enc = (PGPEncryptedDataList) o;
		else
			enc = (PGPEncryptedDataList) pgpF.nextObject();

		// Pronalazenje tajnog kljuca
		Iterator encObjects = enc.getEncryptedDataObjects();

		PGPPrivateKey sKey = null;
		PGPSecretKey secretKey = null;

		while (encObjects.hasNext()) {
			// Pronalazak kljuca koji oddgovara mom privatnom kljucu
			Object obj = encObjects.next();
			if (!(obj instanceof PGPPublicKeyEncryptedData))
				continue;
			PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) obj;
			secretKey = PrstenKljuceva.getPrivateKeyByID(encData.getKeyID());
			// Ako je ID koriscenog kljuca razlicit od nasih kljuceva u prstenu privatnih
			// kljuceva, probaj sledeci
			if (secretKey == null)
				continue;

			// Nasli smo tajni kljuc i sad radimo dohvatanje privatnog, ukoliko je moguce
			sKey = secretKey.extractPrivateKey(passwd, "BC");

			if (sKey != null) {
				// Nasli smo kljuc
				pbe = encData;
				break;
			}
		}

		InputStream clear = pbe.getDataStream(sKey, "BC");

		PGPObjectFactory plainFact = new PGPObjectFactory(clear);

		Object message = plainFact.nextObject();
		Object sigLiteralData = null;
		PGPObjectFactory pgpFact = null;

		// Provera da li je prouka zipovana
		if (message instanceof PGPCompressedData) {
			PGPCompressedData cData = (PGPCompressedData) message;
			pgpFact = new PGPObjectFactory(cData.getDataStream());
			message = pgpFact.nextObject();
			if (message instanceof PGPOnePassSignatureList)
				sigLiteralData = pgpFact.nextObject();
		}

		if (message instanceof PGPLiteralData)
			// Poruka samo enkriptovana
			outFileName = processLiteralData((PGPLiteralData) message, out, null);
		else if (message instanceof PGPOnePassSignatureList) {
			// Poruka enkriptovana i potpisana sa OnePass
			decryptionRes.setIsSigned(true);

			PGPOmotacPotpisa sigWrap = new PGPOmotacPotpisa(((PGPOnePassSignatureList) message).get(0));

			PGPPublicKey pubKey = PrstenKljuceva.getPublicKeyByID(sigWrap.getKeyID());
			if (pubKey == null) {
				decryptionRes.setSignatureException(new Exception(
						"Nema javnog kljuca: [0x" + Integer.toHexString((int) sigWrap.getKeyID()).toUpperCase()
								+ "] u prstenu javnih kljuceva!"));
				outFileName = processLiteralData((PGPLiteralData) sigLiteralData, out, null);
			} else {
				decryptionRes.setSignee(new PPGPPJavniKljuc(pubKey));
				sigWrap.initVerify(pubKey, "BC");
				outFileName = processLiteralData((PGPLiteralData) sigLiteralData, out, sigWrap);
				PGPSignatureList sigList = (PGPSignatureList) pgpFact.nextObject();
				decryptionRes.setIsSignatureValid(sigWrap.verify(sigList.get(0)));
			}
		} else if (message instanceof PGPSignatureList) {
			// Poruka je potpisana i enkriptovana
			decryptionRes.setIsSigned(true);

			PGPOmotacPotpisa sigWrap = new PGPOmotacPotpisa(((PGPSignatureList) message).get(0));

			PGPPublicKey pubKey = PrstenKljuceva.getPublicKeyByID(sigWrap.getKeyID());
			if (pubKey == null) {
				decryptionRes.setSignatureException(new Exception(
						"Nema javnog kljuca: [0x" + Integer.toHexString((int) sigWrap.getKeyID()).toUpperCase()
								+ "] u prstenu javnih kljuceva!"));
				outFileName = processLiteralData((PGPLiteralData) sigLiteralData, out, null);
			} else {
				decryptionRes.setSignee(new PPGPPJavniKljuc(pubKey));
				sigWrap.initVerify(pubKey, "BC");
				sigLiteralData = (PGPLiteralData) pgpFact.nextObject();
				outFileName = processLiteralData((PGPLiteralData) sigLiteralData, out, sigWrap);
				decryptionRes.setIsSignatureValid(sigWrap.verify(null));
			}
		} else
			throw new PGPException("Poruka nije enkriptovan fajl - nepoznat tip.\n(" + message.getClass() + ")");

		if (pbe.isIntegrityProtected())
			if (!pbe.verify())
				throw new Exception("Neuspesna verifikacija poruke.");

		decryptionRes.setDecryptFileName(outFileName);

		return decryptionRes;
	}

	/**
	 * Metoda koja obradu sadrzaja enkriptovane poruke i upis u output fajl
	 * 
	 * @param ld
	 *            Objekat sadrzaja enkriptovane poruke
	 * @param out
	 *            OutputStream fajla za upis dekriptovanog fajla
	 * @param sig
	 *            Objekat omotacke klase PGPSignature
	 * @return Naziv dekriptovanog fajla
	 * @throws IOException
	 * @throws SignatureException
	 */
	private static String processLiteralData(PGPLiteralData ld, OutputStream out, PGPOmotacPotpisa sig)
			throws IOException, SignatureException {
		String outFileName = ld.getFileName();
		InputStream unc = ld.getInputStream();
		int ch;
		if (sig == null)
			while ((ch = unc.read()) >= 0) {
				out.write(ch);
			}
		else
			while ((ch = unc.read()) >= 0) {
				out.write(ch);
				sig.update((byte) ch);
			}

		return outFileName;
	}
}
