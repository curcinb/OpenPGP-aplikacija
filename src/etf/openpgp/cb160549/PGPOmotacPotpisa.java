package etf.openpgp.cb160549;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;

public class PGPOmotacPotpisa {

	/**
	 * Potpis poruke, i da li je on OnePass ili nije
	 */
	PGPOnePassSignature sigOnePass;
	PGPSignature sigOldStyle;
	boolean isOnePass;
	
	/**
	 * Metode koje omotavaju metode klasa PGPSignature i PGPOnePassSignature
	 */

	public PGPOmotacPotpisa(PGPOnePassSignature sigOnePass) {
		this.sigOnePass = sigOnePass;
		isOnePass = true;
	}

	public PGPOmotacPotpisa(PGPSignature sigOldStyle) {
		this.sigOldStyle = sigOldStyle;
		isOnePass = false;
	}

	public void encode(OutputStream outStream) throws IOException {
		int res;
		if (isOnePass == true)
			res = 1;
		else
			res = 0;

		switch (res) {
		case 1:
			sigOnePass.encode(outStream);
			break;
		case 0:
			sigOldStyle.encode(outStream);
			break;
		}
	}

	public byte[] getEncoded() throws IOException {
		return isOnePass ? sigOnePass.getEncoded() : sigOldStyle.getEncoded();
	}

	public int getKeyAlgorithm() {
		return isOnePass ? sigOnePass.getKeyAlgorithm() : sigOldStyle.getKeyAlgorithm();
	}

	public int getHashAlgorithm() {
		return isOnePass ? sigOnePass.getHashAlgorithm() : sigOldStyle.getHashAlgorithm();
	}

	public long getKeyID() {
		return isOnePass ? sigOnePass.getKeyID() : sigOldStyle.getKeyID();
	}

	public long getSignatureType() {
		return isOnePass ? sigOnePass.getKeyID() : sigOldStyle.getKeyID();
	}

	public void initVerify(PGPPublicKey pubKey, String provider) throws NoSuchProviderException, PGPException {
		int res;
		if (isOnePass)
			res = 1;
		else
			res = 0;
		switch (res) {
		case 0:
			sigOldStyle.initVerify(pubKey, provider);
			break;
		case 1:
			sigOnePass.initVerify(pubKey, provider);
			break;

		}
	}

	public void update(byte b) throws SignatureException {
		int res;
		if (isOnePass)
			res = 1;
		else
			res = 0;
		switch (res) {
		case 0:
			sigOldStyle.update(b);
			break;
		case 1:
			sigOnePass.update(b);
			break;
		}
	}

	public void update(byte[] bytes) throws SignatureException {
		int res;
		if (isOnePass)
			res = 1;
		else
			res = 0;
		switch (res) {
		case 0:
			sigOldStyle.update(bytes);
			break;
		case 1:
			sigOnePass.update(bytes);
			break;
		}
	}

	public void update(byte[] bytes, int off, int len) throws SignatureException {
		int res;
		if (isOnePass)
			res = 1;
		else
			res = 0;
		switch (res) {
		case 0:
			sigOldStyle.update(bytes, off, len);
			break;
		case 1:
			sigOnePass.update(bytes, off, len);
			break;
		}
	}

	public boolean verify(PGPSignature pgpSig) throws PGPException, SignatureException {
		return isOnePass ? sigOnePass.verify(pgpSig) : sigOldStyle.verify();
	}
}
