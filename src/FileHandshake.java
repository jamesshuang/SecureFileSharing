/**
 * Provides utility function and constants for handshake protocol
 * between FileClient and FileServer.
 */

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileHandshake {
	public static final Provider CRYPTO_PROVIDER = new BouncyCastleProvider();
	public static final String HMAC_ALG = "HmacSHA256";
	public static final String KEYWRAP_ALG = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	public static final String CIPHER_ALG = "AES/CTR/PKCS5Padding"; // CTR mode prevents blocking on CipherIn/OutputStreams
	public static final int RAND_SIZE = 28; // num. bytes for random exchange for handshake
	public static final int PREMASTER_SIZE = 48; // num. bytes for premaster secret for handshake
	public static final int MASTER_SIZE = 16; // 16 bytes = 128-bit master secret for AES session key

	public static final String INTEG_ALG = "HmacSHA256"; // algorithm for session integrity
	public static final int INTEG_SIZE = 32; // 256 bit session integrity key

	/**
	 * Pseudo-random data expansion function, as defined by RFC 5246, Section 5 --
	 * namely, 'P_SHA256' -- which expands premaster secret and seed into
	 * a shared secret AES key.
	 *
	 * @param secret key for HMAC algorithm
	 * @param seed starting data for expansion (A(0), in RFC terminology)
	 * @return array of keySize bytes
	 */
	public static SecretKey expandKey(Key secret, BigInteger seed, int keySize) {
		Mac hmac;
		byte[] expandedSecret = new byte[keySize];
		try {
			hmac = Mac.getInstance(HMAC_ALG, CRYPTO_PROVIDER);
			hmac.init(secret);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Key expansion error: failed to load HMAC algorithm " + HMAC_ALG + ".");
			return null;
		} catch (InvalidKeyException e) {
			System.err.println("Key expansion error: invalid premaster secret key.");
			return null;
		}

		int lastFilled = 0;
		byte[] nextBytes = { (byte)0x00 }; // A(0) = seed = seed + 0
		while (lastFilled < keySize) {
			// generate A(i) = HMAC(secret, A(i-1) + seed)
			BigInteger newSeed = seed.add(new BigInteger(nextBytes));
			nextBytes = hmac.doFinal(newSeed.toByteArray());

			// concatenate nextBytes to expandedSecret
			for (int i = 0; i < nextBytes.length && lastFilled < keySize; i++, lastFilled++) {
				expandedSecret[lastFilled] = nextBytes[i];
			}
		}

		SecretKey secretKey = new SecretKeySpec(expandedSecret, "AES");
		return secretKey;
	}
}
