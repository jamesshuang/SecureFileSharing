import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EnvelopeAuthority {
	private static final Provider bc = new BouncyCastleProvider();
	static final String DIGEST_ALG = "HmacSHA256";

	private static byte[] calculateHmac(Envelope env, SecretKey key) {
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(bos);  
			oos.writeObject(env.getMessage());
			oos.writeObject(env.getObjContents());
			oos.flush();
			byte[] serializedBytes = bos.toByteArray();

			// make an hmac object using integrity key
			Mac hmac = Mac.getInstance(DIGEST_ALG);
			hmac = Mac.getInstance(DIGEST_ALG, bc);
			hmac.init(key);

			return hmac.doFinal(serializedBytes);
		} catch (Exception e) {
			System.err.println("Failed to calculate envelope HMAC: " + e.getMessage());
			return null;
		}
	}

	public static boolean appendHmac(Envelope env, SecretKey key) {
		byte[] hmac = calculateHmac(env, key);
		if (hmac == null)
			return false;

		env.setHmac(hmac);
		return true;
	}

	public static boolean verifyHmac(Envelope env, SecretKey key) {
		if (env.getHmac() == null) {
			System.err.println("No HMAC on envelope: " + env.getMessage() + ". Ignoring!");
			return false;
		}

		byte[] hmac = calculateHmac(env, key);
		if (hmac == null) { // failed to calculate
			System.err.println("Could not calculate HMAC for envelope: " + env.getMessage() + ". Ignoring!");
			return false;
		}

		// compare stored HMAC with calculated HMAC
		if (!Arrays.equals(hmac, env.getHmac())) {
			System.err.println("Invalid checksum on envelope (" + env.getMessage() + ")!");
			return false;
		}
		return true;
	}

	public static void printHmac(byte[] hmac) {
		System.out.print("HMAC: ");
		for (byte b : hmac)
			System.out.printf("%02x", b & 0xFF);
		System.out.println();
	}
}
