package etf.openpgp.cb160549;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;

//public class PGPDataUtil {
//	public static void writeStreamToLiteralData(OutputStream out, char fileType, InputStream in, int inLength)
//			throws IOException {
//		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
//		OutputStream pOut = lData.open(out, fileType, "Stream", inLength, new Date());
//		byte[] buf = new byte[4096];
//		int len;
//
//		while ((len = in.read(buf)) > 0) {
//			pOut.write(buf, 0, len);
//		}
//
//		lData.close();
//		in.close();
//	}
//}
