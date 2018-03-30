/**
 * Utility class that creates, stores/loads, and allows retrieval of an
 * RSA keypair identity. Can be added to any class that wants to add
 * RSA key handling functionality.
 *
 * As of phase 3, this functionality will be embedded in both group and file servers.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAIdentity
{
	// design-specific algorithm and key length for RSA keys used throughout project
	static private final Provider CRYPTO_PROVIDER = new BouncyCastleProvider(); // BouncyCastle JCA provider
	static private final String KEY_ALG = "RSA";
	static private final String FINGERPRINT_ALG = "SHA-256";
	static private final int KEY_SIZE = 3072;

	private KeyPair keypair;

	/**
	 * Returns the public key associated with this identity.
	 */
	public PublicKey getPublicKey()
	{
		if (keypair == null)
			return null;

		return keypair.getPublic();
	}

	/**
	 * Returns the public key associated with this identity.
	 */
	public PrivateKey getPrivateKey()
	{
		if (keypair == null)
			return null;

		return keypair.getPrivate();
	}
	
	/**
	 * Generates a new keypair to associate with this object.
	 *
	 * @return whether the key generation was successful
	 */
	public boolean generateKeyPair()
	{
		try {
			KeyPairGenerator keygen = KeyPairGenerator.getInstance(KEY_ALG, CRYPTO_PROVIDER);
			keygen.initialize(KEY_SIZE, new SecureRandom());
			keypair = keygen.generateKeyPair();
			return true;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Could not generate keypair: " + e.getMessage());
			keypair = null;
			return false;
		}
	}

	/**
	 * Stores the keypair to disk as a file for later retrieval.
	 *
	 * @param location location to store keypair as file
	 * @return whether the key storage was successful
	 */
	public boolean storeKeyPair(String location)
	{
		if (keypair == null) {
			System.err.println("Error: there is no keypair to store on disk.");
			return false;
		}

		try {
			ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(location));
			out.writeObject(keypair);
			out.close();
			return true;
		} catch (Exception e) {
			System.err.println("Error saving keypair to file " + location + ": " + e.getMessage());
			return false;
		}
	}

	/**
	 * Loads a stored keypair from a file.
	 *
	 * @param location location of keypair stored as file
	 * @return whether the keypair was successfully loaded
	 */
	public boolean loadKeyPair(String location)
	{
		try {
			ObjectInputStream in = new ObjectInputStream(new FileInputStream(location));
			keypair = (KeyPair) in.readObject();
			in.close();
			return true;
		} catch (Exception e) {
			System.err.println("Error loading keypair from file " + location + ": " + e.getMessage());
			return false;
		}
	}

	/**
	 * Write X509 certificate version of public key to a file.
	 */
	public boolean writePublicKeyFile(String location) {
		if (keypair == null) {
			System.err.println("Error: there is no public key to store on disk.");
			return false;
		}

		File f = new File(location);
		if (f.exists()) {
			System.err.println("Public key file already exists at " + location);
			return false;
		}

		try {
			ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(location));
			out.writeObject(keypair.getPublic().getEncoded());
			out.close();
			return true;
		} catch (Exception e) {
			System.err.println("Error saving public key to file " + location + ": " + e.getMessage());
			return false;
		}
	}

	/**
	 * Load X509 certificate version of key back from file.
	 */
	public static PublicKey parsePublicKeyFile(String location) {
		try {
			ObjectInputStream in = new ObjectInputStream(new FileInputStream(location));
			byte[] encodedKey = (byte[]) in.readObject();
			in.close();

			KeyFactory keyfac = KeyFactory.getInstance("RSA");
			PublicKey pubKey = keyfac.generatePublic(new X509EncodedKeySpec(encodedKey));
			return pubKey;
		} catch (Exception e) {
			System.err.println("Error loading keypair from file " + location + ": " + e.getMessage());
			return null;
		}
	}

	/**
	 * Creates a print-friendly hex representation of the SHA256 hash
	 * of the key.
	 *
	 * @param key the key to generate a fingerprint of
	 * @return fingerprint of the key
	 */
	public static String generateFingerprint(Key key)
	{
		byte[] encodedKey = key.getEncoded();

		MessageDigest sha;
		try {
			sha = MessageDigest.getInstance(FINGERPRINT_ALG, CRYPTO_PROVIDER);
		} catch (Exception e) {
			System.err.println("Failed to load digest algorithm " + FINGERPRINT_ALG);
			return null;
		}
		
		byte[] fingerprint = sha.digest(encodedKey);
		return bytesToHexString(fingerprint);
	}

	/**
	 * Utility method: generates a colon-separated hex string from byte array.
	 */
	private static String bytesToHexString(byte[] bytes)
	{
		StringBuilder sb = new StringBuilder(2*bytes.length);
		int counter = 0;
		for (byte b : bytes) {
			sb.append(String.format("%02x", 0xff & b)); // print two digits per byte
			sb.append(":");
		}
		return sb.substring(0, sb.length() - 1); // truncate extra ':'
	}
}
