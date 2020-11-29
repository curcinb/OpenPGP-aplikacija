package etf.openpgp.cb160549;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUtil;

public class PrstenKljuceva {
	
	/**
	 * Ime fajla u kome se cuvaju privatni kljucevi
	 */
	private static final String PRIVATE_KEYRING_FILE = "privatniKljucevi.bpg";
	/**
	 * Ime fajla u kome se cuvaju javni kljucevi
	 */
	private static final String PUBLIC_KEYRING_FILE = "javniKljucevi.bpg";
	/**
	 * Default simetricni algoritam
	 */
	private static final int KEY_ENCRYPTION_ALGO = PGPEncryptedData.CAST5;

	/**
	 * Prsten javnih kljuceva
	 */
	private static PGPPublicKeyRingCollection pubring;
	/**
	 * Prsten privatnih kljuceva
	 */
	private static PGPSecretKeyRingCollection secring;
	/**
	 * Fajl u kome ce da se cuvaju javni kljucevi
	 */
	private static File pubringFile = new File(PUBLIC_KEYRING_FILE);
	/**
	 * Fajl u kome ce da se cuvaju privani kljucevi
	 */
	private static File secringFile = new File(PRIVATE_KEYRING_FILE);

	static {
		Security.addProvider(new BouncyCastleProvider());
		loadKeyrings();
	}

	
	/**
	 * Ucitavanje prstenova javnih i privatnih kljuceva
	 */
	private static void loadKeyrings() {

		String envPub = System.getenv("PUBLIC_KEYRING");
		String envPri = System.getenv("PRIVATE_KEYRING");
		if (envPub != null)
			pubringFile = new File(envPub);
		if (envPri != null)
			secringFile = new File(envPri);

		try {
			secring = new PGPSecretKeyRingCollection(Collections.EMPTY_LIST);
			pubring = new PGPPublicKeyRingCollection(Collections.EMPTY_LIST);
		} catch (IOException | PGPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// Dohvatanje javnog i privatnog prstena kljuceva:
		try {
			if (pubringFile.exists()) {
				InputStream pub_in = new FileInputStream(pubringFile);
				pubring = new PGPPublicKeyRingCollection(pub_in);
				pub_in.close();
			}
			if (secringFile.exists()) {
				InputStream sec_in = new FileInputStream(secringFile);
				secring = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(sec_in));
				sec_in.close();
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * Import javnog kljuca
	 * @param iKeyStream InputStream javnog kljuca
	 * @return	Prsten javnih kljuceva
	 * @throws IOException
	 */
	public static PGPPublicKeyRing importPublicKey(InputStream iKeyStream) throws IOException {
		PGPPublicKeyRing newKey = new PGPPublicKeyRing(iKeyStream);
		pubring = PGPPublicKeyRingCollection.addPublicKeyRing(pubring, newKey);
		OutputStream pub_out;
		try {
			pub_out = new FileOutputStream(pubringFile);
			pubring.encode(pub_out);
			pub_out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return newKey;
	}

	/**
	 * Import privatnog kljuca
	 * @param iKeyStream InputStream privatnog kljuca 
	 * @return Prsten privatnih kljuceva
	 * @throws IOException
	 * @throws PGPException
	 */
	public static PGPSecretKeyRing importPrivateKey(InputStream iKeyStream) throws IOException, PGPException {
		BufferedInputStream iStream = new BufferedInputStream(iKeyStream);

		PGPSecretKeyRing newKey;
		Exception lastException = null;

		iStream.mark(1024 * 128);

		try {
			newKey = new PGPSecretKeyRing(iStream);
			try {
				importPublicKey(iStream);
			} catch (Exception ex2) {
			}
		} catch (IOException ex) {
			iStream.reset();
			try {
				importPublicKey(iStream);
			} catch (Exception ex2) {

			}
			newKey = new PGPSecretKeyRing(iStream);
		}
		secring = PGPSecretKeyRingCollection.addSecretKeyRing(secring, newKey);
		OutputStream sec_out;
		try {
			sec_out = new FileOutputStream(secringFile);
			secring.encode(sec_out);
			sec_out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return newKey;
	}

	/**
	 * Kreiranje novog para javnog i tajnog kljuca
	 * @param iKeySize	Velicina kljuca u bitima
	 * @param iUserID	ID korisnika koji pravi kljuceve
	 * @param iPassphrase	Lozinka pod kojom ce se cuvati privatni kljuc
	 * @throws Exception
	 */
	public static void generateNewKeyPair(int iKeySize, String iUserID, char[] iPassphrase) throws Exception {
		KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA", "BC");
		rsaKpg.initialize(iKeySize);

		KeyPair rsaKp = rsaKpg.generateKeyPair();

		KeyPairGenerator rsa2Kpg = KeyPairGenerator.getInstance("RSA", "BC");
		rsa2Kpg.initialize(iKeySize);
		KeyPair rsa2Kp = rsaKpg.generateKeyPair();

		PGPKeyPair rsaKeyPair = new PGPKeyPair(PGPPublicKey.RSA_SIGN, rsaKp, new Date(), "BC");
		PGPKeyPair rsaKeyPair2 = new PGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsa2Kp, new Date(), "BC");

		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsaKeyPair,
				iUserID, KEY_ENCRYPTION_ALGO, iPassphrase, true /* Use SHA1 */, null /* hashedPcks */,
				null /* unhashedPcks */, new SecureRandom(), "BC");

		keyRingGen.addSubKey(rsaKeyPair2);

		pubring = PGPPublicKeyRingCollection.addPublicKeyRing(pubring, keyRingGen.generatePublicKeyRing());
		OutputStream pub_out;
		try {
			pub_out = new FileOutputStream(pubringFile);
			pubring.encode(pub_out);
			pub_out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		secring = PGPSecretKeyRingCollection.addSecretKeyRing(secring, keyRingGen.generateSecretKeyRing());
		OutputStream sec_out;
		try {
			sec_out = new FileOutputStream(secringFile);
			secring.encode(sec_out);
			sec_out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void changePrivateKeyPassphrase(PGPSecretKeyRing iKeyRing, char[] iOldPassphrase,
			char[] iNewPassphrase) throws PGPException, NoSuchProviderException, IOException {

		PGPSecretKeyRing newKeyring = iKeyRing;
		Iterator i = iKeyRing.getSecretKeys();
		while (i.hasNext()) {
			PGPSecretKey oldKey = (PGPSecretKey) i.next();
			PGPSecretKey newKey = PGPSecretKey.copyWithNewPassword(oldKey, iOldPassphrase, iNewPassphrase,
					KEY_ENCRYPTION_ALGO, new SecureRandom(), "BC");

			newKeyring = PGPSecretKeyRing.removeSecretKey(newKeyring, oldKey);
			newKeyring = PGPSecretKeyRing.insertSecretKey(newKeyring, newKey);
		}

		secring = PGPSecretKeyRingCollection.removeSecretKeyRing(secring,
				secring.getSecretKeyRing(newKeyring.getSecretKey().getKeyID()));
		secring = PGPSecretKeyRingCollection.addSecretKeyRing(secring, newKeyring);

		OutputStream sec_out;
		try {
			sec_out = new FileOutputStream(secringFile);
			secring.encode(sec_out);
			sec_out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Dohvatanje kolekcije prstena javnih kljuceva
	 * @return Kolekcija prstena javnih kljuceva
	 */
	public static Collection<PPGPPrstenJavnihKljuceva> getPublicKeys() {
		Vector<PPGPPrstenJavnihKljuceva> outVec = new Vector<PPGPPrstenJavnihKljuceva>();
		Iterator iter = pubring.getKeyRings();
		while (iter.hasNext()) {
			PGPPublicKeyRing kr = (PGPPublicKeyRing) iter.next();
			outVec.add(new PPGPPrstenJavnihKljuceva(kr));
		}

		return outVec;
	}

	/**
	 * Dohvatanje kolekcije prstena tajnih kljuceva
	 * @return Kolekcija prstena tajnih kljuceva
	 */
	public static Collection<PPGPPrstenTajnihKljuceva> getPrivateKeys() {
		Vector<PPGPPrstenTajnihKljuceva> outVec = new Vector<PPGPPrstenTajnihKljuceva>();
		Iterator iter = secring.getKeyRings();
		while (iter.hasNext()) {
			PGPSecretKeyRing kr = (PGPSecretKeyRing) iter.next();
			outVec.add(new PPGPPrstenTajnihKljuceva(kr));
		}

		return outVec;
	}

	/**
	 * Dohvatanje tajnog kljuca pomocu ID-ja korisnika
	 * @param iID  ID korisnika
	 * @return	Tajni kljuc
	 * @throws PGPException
	 */
	public static PGPSecretKey getPrivateKeyByID(long iID) throws PGPException {
		return secring.getSecretKey(iID);
	}

	/**
	 * Dohvatanje javnog kljuca pomocu ID-ja korisnika
	 * @param iID ID korisnika
	 * @return	Javni kljuc
	 * @throws PGPException
	 */
	public static PGPPublicKey getPublicKeyByID(long iID) throws PGPException {
		return pubring.getPublicKey(iID);
	}

	/**
	 * Brisanje javnog kljuca 
	 * @param iKey Javni kljuc koji je korisnik odabrao
	 * @throws IOException
	 */
	public static void deletePublicKey(PGPPublicKeyRing iKey) throws IOException {
		pubring = PGPPublicKeyRingCollection.removePublicKeyRing(pubring, iKey);
		OutputStream pub_out;
		try {
			pub_out = new FileOutputStream(pubringFile);
			pubring.encode(pub_out);
			pub_out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Brisanje privatnog kljuca
	 * @param iKey Privatni kljuc koji je korisnik odabrao
	 * @throws IOException
	 */
	public static void deletePrivateKey(PGPSecretKeyRing iKey) throws IOException {
		secring = PGPSecretKeyRingCollection.removeSecretKeyRing(secring, iKey);
		OutputStream sec_out;
		try {
			sec_out = new FileOutputStream(secringFile);
			secring.encode(sec_out);
			sec_out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
