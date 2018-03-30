/**
 * A phase-based keychain specific to a single group, including both
 * a confidentiality (encryption) and integrity (HMAC) key for each
 * phase of the group.
 */

import java.io.Serializable;
import java.util.ArrayList;

import javax.crypto.SecretKey;

public class GroupKeychain implements Serializable
{
	static final long serialVersionUID = 7350274360148357238L;

	private String group; // group this keychain corresponds to
	private short phase; // current (most recent) phase stored in keychain
	private ArrayList<SecretKey> encryptionKeys;
	private ArrayList<SecretKey> hmacKeys;

	/**
	 * Constructor.
	 */
	public GroupKeychain(String group, short phase, ArrayList<SecretKey> encKeys, ArrayList<SecretKey> hmacKeys)
	{
		this.group = group;
		this.phase = phase;
		this.encryptionKeys = encKeys;
		this.hmacKeys = hmacKeys;
	}

	/**
	 * Returns the name of the group to which this keychain corresponds.
	 *
	 * @return name of group this keychain belongs to
	 */
	public String getGroupName()
	{
		return group;
	}

	/**
	 * Returns the current phase of this group keychain.
	 */
	public short getPhase()
	{
		return phase;
	}

	/**
	 * Returns the encryption key corresponding to the most recent phase
	 * held by this keychain.
	 *
	 * @return group encryption key for the most recent phase in this keychain
	 */
	public SecretKey getCurrentEncryptionKey()
	{
		return encryptionKeys.get(phase);
	}

	/**
	 * Returns the integrity (HMAC) key corresponding to the most recent phase
	 * held by this keychain.
	 *
	 * @return group HMAC key for the most recent phase in this keychain
	 */
	public SecretKey getCurrentIntegrityKey()
	{
		return hmacKeys.get(phase);
	}

	/**
	 * Returns the group encryption key for this phase, or null if
	 * the requested phase is not in this keychain.
	 *
	 * @param phase which phase of encryption key to get
	 * @return group encryption key for this phase
	 */
	public SecretKey getEncryptionKey(int phase)
	{
		if (phase > this.phase)
			return null;

		return encryptionKeys.get(phase);
	}

	/**
	 * Returns the group integrity (HMAC) key for this phase, or null if
	 * the requested phase is not in this keychain.
	 *
	 * @param phase which phase of HMAC key to get
	 * @return group integrity key for this phase
	 */
	public SecretKey getHmacKey(int phase)
	{
		if (phase > this.phase)
			return null;

		return hmacKeys.get(phase);
	}

	/**
	 * Adds the keys for the next phase of the group to the keychain,
	 * extending the current phase of the keychain to this new phase.
	 *
	 * @param encKey encryption key for the next group phase
	 * @param hmacKey integrity key for the next group phase
	 */
	public void incrementPhase(SecretKey encKey, SecretKey hmacKey)
	{
		phase = (short)(phase + 1);
		encryptionKeys.add(phase, encKey);
		hmacKeys.add(phase, hmacKey);
	}
}
