import java.lang.StringBuilder;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public abstract class Server implements TokenAuthority {

	protected int port;
	public String name;
	abstract void start();

	public Server(int _SERVER_PORT, String _serverName) {
		port = _SERVER_PORT;
		name = _serverName;
	}


	public int getPort() {
		return port;
	}

	public String getName() {
		return name;
	}

	/**
	 * Generates a digest (hash) of the token according to Phase 3 Design doc --
	 * namely, groups are sorted and then fields are concatenated using '+'.
	 *
	 * Private utility method used by sign() and verifySignature().
	 *
	 * @param token the token to calculate a digest from
	 * @return the digest of this token, or null if the digest algorithm is unsupported
	 */
	private byte[] getDigest(UserToken token)
	{
		// extract and sort groups from token
		List<String> groups = token.getGroups();
		Collections.sort(groups);

		// concatenate fields into string
		StringBuilder sb = new StringBuilder();
		sb.append(token.getIssuer());
		sb.append(DIGEST_SEPARATOR);
		sb.append(token.getSubject());
		for (String group : groups) {
			sb.append(DIGEST_SEPARATOR);
			sb.append(group);
		}
		String tokenString = sb.toString();
		
		// generate token digest
		try {
			MessageDigest sha = MessageDigest.getInstance(DIGEST_ALG);
			return sha.digest(tokenString.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Unsupported digest algorithm: " + DIGEST_ALG);
			return null;
		}
	
	}

	/**
	 * "Sign" the token by adding an RSA-signed hash.
	 *
	 * This method can fail if the underlying cipher or digest algorithms
	 * are not supported (although at the time of writing algorithms defined
	 * as mandatory for all Java runtimes are being used).
	 *
	 * @param token the token to sign
	 * @param key the private key to sign the token with
	 * @return whether the signature succeeded
	 */
	public boolean sign(UserToken token, PrivateKey key)
	{
		byte[] digest = getDigest(token);
		if (digest == null) {
			return false;
		}

		// encrypt using provided private key
		try {
			Cipher rsaCipher = Cipher.getInstance(SIGNATURE_ALG);
			rsaCipher.init(Cipher.ENCRYPT_MODE, key);

			// set the token signature field
			token.setSignature(rsaCipher.doFinal(digest));
			return true;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Unsupported signing algorithm: " + SIGNATURE_ALG);
			return false;
		} catch (Exception e) {
			System.err.println("Error signing the token: " + e.getMessage());
			return false;
		}
	}

	/**
	 * Verify the signature attached to this token by decrypting it and
	 * comparing it to a newly calculated digest; this ensures that the
	 * token has not been tampered with since being signed.
	 *
	 * This method can fail if the underlying cipher or digest algorithms
	 * are not supported (although at the time of writing algorithms defined
	 * as mandatory for all Java runtimes are being used).
	 *
	 * @param key the public key to use in verifying the token's signature
	 * @return whether the token has a valid signed digest
	 */
	public boolean verifySignature(UserToken token, PublicKey key)
	{
		byte[] digest = getDigest(token);
		if (digest == null) {
			return false;
		}
	
		// decrypt stored digest using provided public key
		try {
			Cipher rsaCipher = Cipher.getInstance(SIGNATURE_ALG);
			rsaCipher.init(Cipher.DECRYPT_MODE, key);
			byte[] signedDigest = rsaCipher.doFinal(token.getSignature());

			// compare the stored digest and the newly calculated one
			return Arrays.equals(digest, signedDigest);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Unsupported signing algorithm: " + SIGNATURE_ALG);
			return false;
		} catch (Exception e) {
			System.err.println("Error signing the token: " + e.getMessage());
			return false;
		}
	}
}
