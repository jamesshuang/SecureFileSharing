import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Specification for servers that act as token authorities,
 * namely specifying signing and signature verification methods.
 */

public interface TokenAuthority
{
	// design-specified algorithms and concatenation character
	// for calculating token digests and signing
	static final String DIGEST_SEPARATOR = "+";
	static final String DIGEST_ALG = "SHA-256";
	static final String SIGNATURE_ALG = "RSA/ECB/PKCS1Padding";

    /**
	 * Populates the signature field of the token with a
	 * byte array representing the signed digest of
	 * the token's fields.
	 *
	 * Operates according to the spec in doc/phase3-writeup.md.
     *
	 * @param token the token to sign
	 * @param key the private key to use in signing the token
     * @return whether the signing process succeeded
     */
	public boolean sign(UserToken token, PrivateKey key);

    /**
	 * Compares the calculated digest of a token with the
	 * signed digest in the token's signature field.
	 *
	 * Fails if either the token is unsigned or if the calculated
	 * digest does not match the signed digest.
	 *
	 * Operates according to the spec in doc/phase3-writeup.md.
     *
	 * @param token the token to verify
	 * @param key the public key to use in verifying the token's signature
     * @return whether the token's signature is valid
     */
	public boolean verifySignature(UserToken token, PublicKey key);
}
