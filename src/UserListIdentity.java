import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import javax.crypto.SealedObject;
import javax.crypto.Cipher;
import java.io.FileNotFoundException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class UserListIdentity {
  // design-specific algorithm and key length for RSA keys used throughout project
	static private final Provider CRYPTO_PROVIDER = new BouncyCastleProvider(); // BouncyCastle JCA provider
	static private final String KEY_ALG = "AES";
	static private final int KEY_SIZE = 256;

	private SecretKey key;
  
  /**
   * Returns the secret key assoicated with this UserListKeyIdentity
   *
   * @return SecretKey
   */
  public SecretKey getKey() {
    return key;
  }
  
	/**
	 * Generates a new key to associate with this object.
	 *
	 * @return whether the key generation was successful
	 */
	public boolean generateKey()
	{
		try {
			KeyGenerator keygen = KeyGenerator.getInstance(KEY_ALG, CRYPTO_PROVIDER);
			keygen.init(KEY_SIZE);
			key = keygen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Could not generate key: " + e.getMessage());
			key = null;
			return false;
		}
    storeKey();
    return true;
	}

	/**
	 * Stores the keypair to disk as a file for later retrieval.
	 *
	 * @return whether the key storage was successful
	 */
	public boolean storeKey()
	{
    String location = "UserListKey.bin";
		if (key == null) {
			System.err.println("Error: there is no key to store on disk.");
			return false;
		}

		try {
			ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(location));
			out.writeObject(key);
			out.close();
			return true;
		} catch (Exception e) {
			System.err.println("Error saving key to file " + location + ": " + e.getMessage());
			return false;
		}
	}

	/**
	 * Loads a stored key from a file.
	 *
	 * @return whether the key was successfully loaded
	 */
	public boolean loadKey()
	{
    String location = "UserListKey.bin";
		try {
			ObjectInputStream in = new ObjectInputStream(new FileInputStream(location));
			key = (SecretKey) in.readObject();
			in.close();
			return true;
		} catch (Exception e) {
			System.err.println("Error loading key from file " + location + ": " + e.getMessage());
			return false;
		}
	}
  
  /** 
   * Saves UserList object to a file called "UserList.bin"
   *
   * @return true if successful, false otherwise
   */
  public boolean save(UserList userList) throws Exception {
    boolean storeKey = storeKey();
    if (!storeKey) {
      System.out.println("Failed to store userlist key");
      return false;
    }
    
    Cipher cipher = Cipher.getInstance(KEY_ALG, CRYPTO_PROVIDER);
    cipher.init(Cipher.ENCRYPT_MODE, key);
    SealedObject list = new SealedObject(userList, cipher);
    
    ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("UserList.bin")));
    oos.writeObject(list);
    oos.close();
    return true;
  }
  
  /**
   * Loads UserList.bin file
   *
   * @return UserList from file
   */
  public UserList load() throws Exception {
    boolean loadKey = loadKey();
    if (!loadKey) {
      System.out.println("Failed to load userlist key");
      throw new FileNotFoundException();
    }
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File("UserList.bin")));
    SealedObject sealed = (SealedObject)ois.readObject();
    ois.close();
    
    Cipher cipher = Cipher.getInstance(KEY_ALG, CRYPTO_PROVIDER);
    cipher.init(Cipher.DECRYPT_MODE, key);
    
    UserList userList = (UserList)sealed.getObject(cipher);
    return userList;
  }
  
   
}