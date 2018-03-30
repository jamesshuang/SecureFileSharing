/* Implements the GroupClient Interface */

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.Exception;
import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.Key;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.zip.InflaterInputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupClient extends Client implements GroupClientInterface {

	private static final Provider bc = new BouncyCastleProvider();
	SecretKey sharedSecret;
	SecretKey sessionIntegrityKey;
	
	//sequences numbers will be initialized by numbers received from group server at the end of handshake
	private int threadNumStart;
	private static int clientNumStart = 1;
	
	private Sequence threadNum;
	private Sequence clientNum;

	/*
	 * Aquire new user token. Handshake must be performed before user can 
	 * get a new token, otherwise method will be unsuccessful
	 *
	 * @return UserToken of requested username
	 */
	public UserToken getToken(String username, String serverName, int serverPort)
	{
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(serverName);
			message.addObject((Integer)serverPort);
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();

			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if(temp.size() == 2)
				{
					token = (Token)temp.get(0);
					//invalid message due to incorrect sequence number
					if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
						return null;
					}
					return token;
				}
			}

			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	}

	/**
	 * Gets the user's keychain, containing keychains for each group the user is
	 * a member of.
	 *
	 * @return the user keychain, or null on error
	 */
	@SuppressWarnings("unchecked")
	public Map<String, GroupKeychain> getUserKeychain(UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to create a user
			message = new Envelope("KEYS");
			message.addObject(token); //Add the requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

			output.writeObject(message);

			response = (Envelope)input.readObject();

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return null;
				}
				
				byte[] compressedKeychain = (byte[]) response.getObjContents().get(0);
				if (compressedKeychain != null) {
					// decompress keychain
					ByteArrayInputStream bis = new ByteArrayInputStream(compressedKeychain);
					InflaterInputStream dis = new InflaterInputStream(bis);
					ObjectInputStream ois = new ObjectInputStream(dis);  
					Map<String, GroupKeychain> keychain = (Map<String, GroupKeychain>) ois.readObject();
					return keychain;
				}
			}

			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	/*
	 * Perform the handshake operation. After handshake is successful, user
	 * user will be able to retreive their token by calling the getToken method
	 * 
	 * Method will also establish a new shared secret with the server,
	 * which can be used to encrypt and decrypt future exchanges
	 *
	 * @return true on successful handshake, false otherwise
	 */
	public boolean handshake(String username, String password)
	{
		try
		{
			Envelope message = null, response = null;

			byte[] passwordHash = null;
			MessageDigest hash = MessageDigest.getInstance("SHA-256", bc);
			passwordHash = hash.digest(password.getBytes("UTF-8"));

			//let's start EKE
			DHIdentity client = new DHIdentity();
			byte[] startExchange = client.send();

			//let's encrypt the start of our diffie exchange with our hashed password
			SecretKeySpec passwordKey = new SecretKeySpec(passwordHash, "AES");
			Cipher cipher = Cipher.getInstance("AES", bc);
			cipher.init(Cipher.ENCRYPT_MODE, passwordKey);
			byte[] encryptedStart = cipher.doFinal(startExchange);

			// initiate the handshake
			message = new Envelope("HANDSHAKE");
			message.addObject(username); //Add user name string
			message.addObject(encryptedStart); //add start of Diffie Hellman exchange
			output.writeObject(message);

			//Wait for response from server, reponse will include challenge #1
			response = (Envelope)input.readObject();

			//let's see what is in the response
			byte[] diffieEncrypted = null;
			byte[] diffieDecrypted = null;
			BigInteger c1 = null;
			if(response.getMessage().equals("DIFFIE_RESPONSE")) {
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				diffieEncrypted = (byte[])temp.get(0);
				try {
					cipher.init(Cipher.DECRYPT_MODE, passwordKey);
					diffieDecrypted = cipher.doFinal(diffieEncrypted);
				}
				catch (Exception e) {
					//we should probably return if decryption fails (might not be server we're talking to)
					return false;
				}
				byte[] encryptedC1 = (byte[])temp.get(1);
				cipher.init(Cipher.DECRYPT_MODE, passwordKey);
				c1 = new BigInteger(cipher.doFinal(encryptedC1));
			}
			else {
				System.out.println("Failed to get token");
				return false;
			}

			//we can now generate our shared secret with the server
			sharedSecret = client.generateSharedSecret(diffieDecrypted);

			// establish secure input/output streams using new shared secret
			// generate IV for cipher from c1
			AlgorithmParameterSpec ivSpec = new IvParameterSpec(c1.toByteArray(), 0, 16);

			// wrap the socket input/output streams with a cipher
			Cipher outCipher = Cipher.getInstance(DHIdentity.CIPHER_ALG);
			outCipher.init(Cipher.ENCRYPT_MODE, sharedSecret, ivSpec);
			CipherOutputStream cos = new CipherOutputStream(sock.getOutputStream(), outCipher);
			Cipher inCipher = Cipher.getInstance(DHIdentity.CIPHER_ALG);
			inCipher.init(Cipher.DECRYPT_MODE, sharedSecret, ivSpec);
			CipherInputStream cis = new CipherInputStream(sock.getInputStream(), inCipher);

			// reroute the client input/output streams through the new cipher streams
			output = new ObjectOutputStream(cos);
			output.flush();
			output.writeObject(c1); // write filler bytes to force flush
			output.flush(); // push through ObjectStream headers
			input = new ObjectInputStream(cis);
			BigInteger filler = (BigInteger) input.readObject(); // read and toss filler

			//let's generate our 128 bit challenge c2
			SecureRandom rand = new SecureRandom();
			BigInteger c2 = new BigInteger(128, rand);

			//reply to server with challenges
			message = new Envelope("CHALLENGE");
			message.addObject(c1); 
			message.addObject(c2); 
			message.addObject((Integer)clientNumStart);
			output.writeObject(message);

			// wait for server to authenticate
			response = (Envelope)input.readObject();

			if (!response.getMessage().equals("OK")) {
				System.err.println("Invalid challenge response from server.");
				return false;
			}

			ArrayList<Object> temp = null;
			temp = response.getObjContents();

			BigInteger c2Response = (BigInteger)temp.get(0);
			threadNumStart = (Integer)temp.get(1);
			
			threadNum = new Sequence(threadNumStart);
			clientNum = new Sequence(clientNumStart);

			//finally, let's confirm that the returned challenge matches the sent challenge
			if (!c2.equals(c2Response)) {
				System.out.println("Server failed authentication. Disconnecting...");
				disconnect();
				return false;
			}

			// session integrity key is C1 XOR C2
			byte[] cXor = c1.xor(c2).toByteArray();
			sessionIntegrityKey = new SecretKeySpec(cXor, "HmacSHA256");

			return true;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}

	}

	private byte[] encrypt(byte[] toEncrypt) throws Exception{
		Cipher cipher = Cipher.getInstance("AES", bc);
		cipher.init(Cipher.ENCRYPT_MODE, sharedSecret);
		return cipher.doFinal(toEncrypt);
	}

	private byte[] decrypt(byte[] toDecrypt) throws Exception{
		Cipher cipher = Cipher.getInstance("AES", bc);
		cipher.init(Cipher.DECRYPT_MODE, sharedSecret);
		return cipher.doFinal(toDecrypt);
	}

	public String createUser(String username, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to create a user
			message = new Envelope("CUSER");
			message.addObject(username); //Add user name string
			message.addObject(token); //Add the requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

			output.writeObject(message);

			response = (Envelope)input.readObject();

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return null;
				}
				
				return (String)response.getObjContents().get(0);
			}

			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean deleteUser(String username, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;

			//Tell the server to delete a user
			message = new Envelope("DUSER");
			message.addObject(username); //Add user name
			message.addObject(token);  //Add requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

			output.writeObject(message);

			response = (Envelope)input.readObject();

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return false;
				}
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean createGroup(String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to create a group
			message = new Envelope("CGROUP");
			message.addObject(groupname); //Add the group name string
			message.addObject(token); //Add the requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);
			
			output.writeObject(message);

			response = (Envelope)input.readObject();

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return false;
				}
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	/**
	 * Sends a request to rekey a specific group.
	 *
	 * @param groupname group to rekey
	 * @param token user token corresponding to group owner
	 * @return true if the rekey was successful, false otherwise
	 */
	public boolean rekeyGroup(String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to rekey the group
			message = new Envelope("REKEY");
			message.addObject(groupname); //Add the group name string
			message.addObject(token); //Add the requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

			output.writeObject(message);

			response = (Envelope)input.readObject();

			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return false;
				}
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteGroup(String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to delete a group
			message = new Envelope("DGROUP");
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

			output.writeObject(message);

			response = (Envelope)input.readObject();
			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return false;
				}
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to return the member list
			message = new Envelope("LMEMBERS");
			message.addObject(group); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

			output.writeObject(message);

			response = (Envelope)input.readObject();

			//If server indicates success, return the member list
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				List<String> usersList = (List<String>)temp.get(0); 

				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return null;
				}
				
				return usersList;
			}

			return null;

		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean addUserToGroup(String username, String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP");
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

			output.writeObject(message);

			response = (Envelope)input.readObject();
			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return false;
				}
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	{
		try
		{
			Envelope message = null, response = null;
			//Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			message.addObject(username); //Add user name string
			message.addObject(groupname); //Add group name string
			message.addObject(token); //Add requester's token
			message.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

			output.writeObject(message);

			response = (Envelope)input.readObject();
			//If server indicates success, return true
			if(response.getMessage().equals("OK"))
			{
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				//invalid message due to incorrect sequence number
				if (checkValid(temp) == false || EnvelopeAuthority.verifyHmac(response, sessionIntegrityKey) == false) {
					return false;
				}
				return true;
			}

			return false;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}
	
	public boolean checkValid(ArrayList<Object> response) {
		int index = response.size() - 1;
		if (clientNum.valid((Integer)response.get(index)) == false) {
			System.out.println("Warning: Invalid sequence number from group thread!");
			return false;
		}
		else 
			return true;
	}
}
