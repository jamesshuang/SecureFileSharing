/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */

import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.Exception;
import java.lang.Thread;
import java.math.BigInteger;
import java.net.Socket;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;
import java.util.zip.DeflaterOutputStream;
import java.lang.reflect.Array;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;
	private final RSAIdentity rsaId;
	private static final Provider bc = new BouncyCastleProvider();
	SecretKey sharedSecret;
	SecretKey sessionIntegrityKey;
	
	//sequence numbers to protect message replay/reorder attacks
	//initalize to 100 because numbers do not need to be random
	private int threadNumStart = 1;
	private int clientNumStart;

	private Sequence clientNum;
	private Sequence threadNum;

	public GroupThread(Socket _socket, GroupServer _gs, RSAIdentity rsaId)
	{
		socket = _socket;
		my_gs = _gs;
		this.rsaId = rsaId;
	}

	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());

				// prevent the outputstream from caching previously sent objects -- send fresh on each loop iteration
				output.reset();

				switch(message.getMessage()) {
					case "GET":
						{
							String username = (String)message.getObjContents().get(0); //Get the username
							String serverName = (String)message.getObjContents().get(1);
							int serverPort = (int)message.getObjContents().get(2);
							
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							
							if(username == null) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							UserToken token = createToken(username, serverName, serverPort); //Create a token
							my_gs.sign(token, rsaId.getPrivateKey()); // have server sign the token

							//Respond to the client. On error, the client will receive a null token
							Envelope response = new Envelope("OK");
							response.addObject(token);
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
							output.writeObject(response);			
						}
						break;
					case "HANDSHAKE":
						{
							if (!my_gs.shouldAcceptConnection(socket.getInetAddress().toString())) {
								Envelope response = new Envelope("CONNECTION-DENIED");
								EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
								output.writeObject(response);

								System.out.println("Disconnecting from blacklisted IP " + socket.getInetAddress());
								proceed = false;
								break;
							}

							String username = (String)message.getObjContents().get(0); //Get the username
							byte[] encryptedBytes = (byte[])message.getObjContents().get(1); //grab start of diffie_start

							if(username == null || !userExists(username)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							//let's decrypt the message we received with the user's hashed password
							byte[] password = getPassword(username);							
							SecretKeySpec passwordKey = new SecretKeySpec(password, "AES");
							Cipher cipher = Cipher.getInstance("AES", bc);
							cipher.init(Cipher.DECRYPT_MODE, passwordKey);
							byte[] decryptedStart = null;

							try {
								decryptedStart = cipher.doFinal(encryptedBytes);
							} catch (Exception e) {
								System.out.println("Invalid handshake attempt from user.");
								my_gs.registerFailedConnectionAttempt(socket.getInetAddress().toString());
								respondFailure(output);
								proceed = false;
								break;
							}

							DHIdentity serverDiffie = new DHIdentity();

							byte[] diffieResponse = serverDiffie.receive(decryptedStart);

							//let's generate our shared secret
							sharedSecret = serverDiffie.generateSharedSecret(decryptedStart);

							//let's generate our 128 bit challenge c1 and encrypt it with user's hashed password
							SecureRandom rand = new SecureRandom();
							BigInteger c1 = new BigInteger(128, rand);

							Envelope response = new Envelope("DIFFIE_RESPONSE");
							cipher.init(Cipher.ENCRYPT_MODE, passwordKey);
							response.addObject(cipher.doFinal(diffieResponse));

							cipher.init(Cipher.ENCRYPT_MODE, passwordKey);
							byte[] c1Enc = cipher.doFinal(c1.toByteArray());
							response.addObject(c1Enc);

							output.writeObject(response);

							// establish secure input/output streams using new shared secret
							// generate IV for cipher from c1
							AlgorithmParameterSpec ivSpec = new IvParameterSpec(c1.toByteArray(), 0, 16);

							// wrap the socket input/output streams with a cipher
							Cipher outCipher = Cipher.getInstance(DHIdentity.CIPHER_ALG);
							outCipher.init(Cipher.ENCRYPT_MODE, sharedSecret, ivSpec);
							CipherOutputStream cos = new CipherOutputStream(socket.getOutputStream(), outCipher);
							Cipher inCipher = Cipher.getInstance(DHIdentity.CIPHER_ALG);
							inCipher.init(Cipher.DECRYPT_MODE, sharedSecret, ivSpec);
							CipherInputStream cis = new CipherInputStream(socket.getInputStream(), inCipher);

							// reroute the client input/output streams through the new cipher streams
							output = new ObjectOutputStream(cos);
							output.flush(); // push through ObjectStream headers
							output.writeObject(c1); // write filler bytes to force flush
							output.flush(); // push through ObjectStream headers
							input = new ObjectInputStream(cis);
							BigInteger filler = (BigInteger)input.readObject(); // read and toss filler

							//let's wait for our reponse back
							response = (Envelope)input.readObject();

							// grab c1 and c2, which should be properly decrypted at this point 
							BigInteger c1Response;
							BigInteger c2;
							if(response.getMessage().equals("CHALLENGE")) {
								ArrayList<Object> temp;
								temp = response.getObjContents();
								c1Response = (BigInteger)temp.get(0);
								c2= (BigInteger)temp.get(1);
								clientNumStart = (Integer)temp.get(2);
								clientNum = new Sequence(clientNumStart);
								threadNum = new Sequence(threadNumStart);
							} else {
								System.out.println("User failed to authenticate.");
								my_gs.registerFailedConnectionAttempt(socket.getInetAddress().toString());
								proceed = false; //End this communication loop
								break;
							}

							if (c1Response.equals(c1)) {
								System.out.println("User successfully authenticated");
							} else {
								System.out.println("User failed to authenticate.");
								my_gs.registerFailedConnectionAttempt(socket.getInetAddress().toString());
								proceed = false; //End this communication loop
								break;
							}

							// session integrity key is C1 XOR C2
							byte[] cXor = c1.xor(c2).toByteArray();
							sessionIntegrityKey = new SecretKeySpec(cXor, "HmacSHA256");

							response = new Envelope("OK");
							response.addObject(c2);
							response.addObject((Integer)threadNumStart);
							output.writeObject(response);							
						}
						break;
					case "KEYS":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 2) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							UserToken token = (UserToken)message.getObjContents().get(0); //Extract the token
							
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							
							if (token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							Map<String, GroupKeychain> keychain = getUserKeychain(token);

							// compress keychain for transmission
							ByteArrayOutputStream bos = new ByteArrayOutputStream();
							DeflaterOutputStream dos = new DeflaterOutputStream(bos);
							ObjectOutputStream oos = new ObjectOutputStream(dos);  
							oos.writeObject(keychain);
							oos.flush();
							dos.finish();
							byte[] compressedKeychain = bos.toByteArray();

							Envelope response = new Envelope("OK");
							response.addObject(compressedKeychain);
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
							output.writeObject(response);			
						}
						break;
					case "CUSER":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 3) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// make sure we have a username and a token
							String username = (String)message.getObjContents().get(0); //Extract the username
							UserToken token = (UserToken)message.getObjContents().get(1); //Extract the token
							if (username == null || token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// attempt to create the user
							String password = createUser(username, token);
							if (password == null) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							Envelope response = new Envelope("OK");
							response.addObject(password);
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);

							output.writeObject(response);
						}
						break;
					case "DUSER":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 3) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// make sure we have a username and a token
							String username = (String)message.getObjContents().get(0); //Extract the username
							UserToken token = (UserToken)message.getObjContents().get(1); //Extract the token
							if (username == null || token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// attempt to delete the user
							boolean success = deleteUser(username, token);
							if (!success) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							Envelope response = new Envelope("OK");
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);

							output.writeObject(response);
						}
						break;
					case "CGROUP":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 3) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// make sure we have a group name and a token
							String groupname = (String)message.getObjContents().get(0); //Extract the groupname
							UserToken token = (UserToken)message.getObjContents().get(1); //Extract the token
							if (groupname == null || token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// attempt to create the group
							boolean success = createGroup(groupname, token);
							if (!success) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							Envelope response = new Envelope("OK");
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);

							output.writeObject(response);
						}
						break;
					case "DGROUP":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 3) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// make sure we have a group name and a token
							String groupname = (String)message.getObjContents().get(0); //Extract the groupname
							UserToken token = (UserToken)message.getObjContents().get(1); //Extract the token
							if (groupname == null || token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// attempt to create the group
							boolean success = deleteGroup(groupname, token);
							if (!success) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							Envelope response = new Envelope("OK");
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);

							output.writeObject(response);
						}
						break;
					case "REKEY":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 3) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// make sure we have a group name and a token
							String groupname = (String)message.getObjContents().get(0); //Extract the groupname
							UserToken token = (UserToken)message.getObjContents().get(1); //Extract the token
							if (groupname == null || token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// attempt to rekey the group
							boolean success = rekeyGroup(groupname, token);
							if (!success) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							Envelope response = new Envelope("OK");
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);

							output.writeObject(response);
						}
						break;
					case "LMEMBERS":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 3) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// make sure we have a group name and a token
							String groupname = (String)message.getObjContents().get(0); //Extract the groupname
							UserToken token = (UserToken)message.getObjContents().get(1); //Extract the token
							if (groupname == null || token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// attempt to get the list of members
							List<String> members = listMembers(groupname, token);
							if (members == null) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							Envelope response = new Envelope("OK");
							response.addObject(members);
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);

							output.writeObject(response);
						}
						break;
					case "AUSERTOGROUP":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 4) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// make sure we have a username, group name, and token
							String username = (String)message.getObjContents().get(0); //Extract the username
							String groupname = (String)message.getObjContents().get(1); //Extract the groupname
							UserToken token = (UserToken)message.getObjContents().get(2); //Extract the token
							if (username == null || groupname == null || token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// attempt to add the user to the group
							boolean success = addUserToGroup(username, groupname, token);
							if (!success) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							Envelope response = new Envelope("OK");
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);

							output.writeObject(response);
						}
						break;
					case "RUSERFROMGROUP":
						{
							// make sure request is correct size
							if(message.getObjContents().size() < 4) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// make sure we have a username, group name, and token
							String username = (String)message.getObjContents().get(0); //Extract the username
							String groupname = (String)message.getObjContents().get(1); //Extract the groupname
							UserToken token = (UserToken)message.getObjContents().get(2); //Extract the token
							if (username == null || groupname == null || token == null || !isValidToken(token)) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							if (checkValid(message.getObjContents()) == false || EnvelopeAuthority.verifyHmac(message, sessionIntegrityKey) == false) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}

							// attempt to remove the user from the group
							boolean success = removeUserFromGroup(username, groupname, token);
							if (!success) {
								respondFailure(output);
								continue; // proceed to next incoming request
							}
							Envelope response = new Envelope("OK");
							response.addObject(clientNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);

							output.writeObject(response);
						}
						break;
					case "DISCONNECT":
						socket.close(); //Close the socket
						proceed = false; //End this communication loop
						break;
					default:
						Envelope response = new Envelope("FAIL"); //Server does not understand client request
						response.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
						output.writeObject(response);
						break;
				}
			} while (proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private byte[] encrypt(byte[] toEncrypt) throws Exception{
		Cipher cipher = Cipher.getInstance("AES", bc);
		cipher.init(Cipher.ENCRYPT_MODE, sharedSecret);
		return cipher.doFinal(toEncrypt);
	}

	private byte[] getPassword(String username) {
		return my_gs.userList.getUserPassword(username);
	}
	/**
	 * Sends a "FAIL" message to the connected client.
	 */
	private void respondFailure(ObjectOutputStream output) {
		try {
			Envelope response = new Envelope("FAIL");
			if (clientNum != null)
				response.addObject(clientNum.getSequenceNum());
			if (sessionIntegrityKey != null)
				EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
			output.writeObject(response);
		} catch (Exception e) {
			// if we can't even submit a failure, we're in trouble...
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	/**
	 * Creates a token for the requesting user if the user account has been created.
	 *
	 * @param username the user
	 * @return the token for username
	 */
	private UserToken createToken(String username, String serverName, int serverPort)
	{
		if (userExists(username)) {
			
			//serverName and serverPort will be null if request for token
			//is for a group server action, so let's initialize to prevent error
			if (serverName == null) {
				serverName = "";
				serverPort = 0;
			}
			// Issue a new token with server's name, user's name, and user's groups
			UserToken token = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), serverPort, serverName);
			return token;
		} else {
			return null;
		}
	}

	/**
	 * Attempts to remove the specified user from the specified group
	 * using the permissions associated with the token.
	 *
	 * @param user the user
	 * @param group the group from which this user should be removed
	 * @param token the requesting user's token
	 * @return true if the user is successfully removed from the group, false otherwise
	 */
	private boolean removeUserFromGroup(String user, String group, UserToken token) {
		String requester = token.getSubject();

		// Make sure that the user to be removed from the group exists.
		if (!userExists(user))
			return false;

		// Check that a group with this name exists
		if (!my_gs.userList.groupExists(group)) {
			System.err.println("A group with the name '" + group + "' does not exist -- permission denied.");
			return false;
		}

		// Make sure the requesting user exists and owns this group.
		if (!userExists(requester) || !ownsGroup(requester, group))
			return false;

		my_gs.userList.removeUserFromGroup(user, group);
		return true;
	}

	/**
	 * Attempts to add the specified user as a member to the specified group
	 * using the permissions associated with the token.
	 *
	 * @param user the user
	 * @param group the group to which the user should be added as member
	 * @param token the requesting user's token
	 * @return true if the user is successfully added to the group, false otherwise
	 */
	private boolean addUserToGroup(String user, String group, UserToken token) {
		String requester = token.getSubject();

		// Make sure that the user to be added to the group exists.
		if (!userExists(user))
			return false;

		// Check that a group with this name exists
		if (!my_gs.userList.groupExists(group)) {
			System.err.println("A group with the name '" + group + "' does not exist -- permission denied.");
			return false;
		}

		// Make sure the requesting user exists and owns this group.
		if (!userExists(requester) || !ownsGroup(requester, group))
			return false;

		my_gs.userList.addUserToGroup(user, group);
		return true;
	}

	/**
	 * Returns a list of members in the specified group, if the requester
	 * has permission to view this group's information.
	 *
	 * @param group the group
	 * @param token the token of the user requesting the list of group members
	 * @return list of members in this group, or null if the group doesn't exist or the requester doesn't have permission to view this group
	 */
	private List<String> listMembers(String group, UserToken token) {
		String requester = token.getSubject();

		// Check that a group with this name exists
		if (!my_gs.userList.groupExists(group)) {
			System.err.println("A group with the name '" + group + "' does not exist -- permission denied.");
			return null;
		}

		List<String> groupMembers = my_gs.userList.getGroupMembers(group);

		// Check that the user is either the group owner or a member of the group
		if (!groupMembers.contains(requester) && !ownsGroup(requester, group)) {
			System.err.println("User '" + requester + "' is neither a member nor owner of the group '" + group + "' -- permission denied.");
			return null;
		}

		return groupMembers;
	}

	/**
	 * Attempts to create a new group with the permissions of the requester.
	 *
	 * Fails if a group with this name already exists.
	 *
	 * @param group name of the new group
	 * @param token the token of the user requesting to create the group
	 * @return true if the new group is created, false otherwise
	 */
	private boolean createGroup(String group, UserToken token)
	{
		String requester = token.getSubject();

		// Make sure the requesting user exists
		if (!userExists(requester))
			return false;

		// Check that a group with this name does not already exist
		if (my_gs.userList.groupExists(group)) {
			System.err.println("A group with the name '" + group + "' already exists -- permission denied.");
			return false;
		}

		my_gs.userList.createGroup(group, requester);
		boolean success = rekeyGroup(group, token); // generate keychain and starting keys for new group

		return success;
	}


	/**
	 * Attempts to delete a group.
	 *
	 * @param group the group to delete
	 * @param token the token of the user requesting the deletion
	 * @return true if the deletion succeeds, false otherwise
	 */
	private boolean deleteGroup(String group, UserToken token)
	{
		String requester = token.getSubject();

		// Check that a group with this name exists
		if (!my_gs.userList.groupExists(group)) {
			System.err.println("A group with the name '" + group + "' does not exist -- permission denied.");
			return false;
		}

		// Make sure the requesting user exists and owns this group.
		if (!userExists(requester) || !ownsGroup(requester, group))
			return false;

		// Do the deletion
		my_gs.userList.removeOwnership(requester, group);
		my_gs.userList.deleteGroup(group);
		my_gs.groupKeychains.remove(group);
		return true;
	}

	/**
	 * Attempts to rekey a group.
	 *
	 * @param group the group to rekey
	 * @param token the token of the user requesting the rekey
	 * @return true if the rekey succeeds, false otherwise
	 */
	private boolean rekeyGroup(String group, UserToken token)
	{
		String requester = token.getSubject();

		// Check that a group with this name exists
		if (!my_gs.userList.groupExists(group)) {
			System.err.println("A group with the name '" + group + "' does not exist -- permission denied.");
			return false;
		}

		// Make sure the requesting user exists and owns this group.
		if (!userExists(requester) || !ownsGroup(requester, group))
			return false;

		// Generate keys for the new phase and add them to the group keychain
		SecretKey newEncKey;
		SecretKey newHmacKey;
		try {
			KeyGenerator encKeygen = KeyGenerator.getInstance("AES", bc);
			encKeygen.init(128);
			newEncKey = encKeygen.generateKey();

			KeyGenerator hmacKeygen = KeyGenerator.getInstance("HmacSHA256", bc);
			hmacKeygen.init(128);
			newHmacKey = hmacKeygen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Failed to rekey group " + group + "!");
			return false;
		}

		GroupKeychain groupKeychain = my_gs.groupKeychains.get(group);
		if (groupKeychain == null) { // no keychain exists yet for this group
			// create a new group keychain for this group, starting at phase 0
			ArrayList<SecretKey> encKeys = new ArrayList<SecretKey>();
			encKeys.add(newEncKey);
			ArrayList<SecretKey> hmacKeys = new ArrayList<SecretKey>();
			hmacKeys.add(newHmacKey);
			groupKeychain = new GroupKeychain(group, (short) 0, encKeys, hmacKeys);
			
			// add the group keychain to the group server's keychain store
			my_gs.groupKeychains.put(group, groupKeychain);
		} else {
			// increment the phase of the existing group keychain
			groupKeychain.incrementPhase(newEncKey, newHmacKey);
		}

		return true;
	}

	/**
	 * Creates a user-specific keychain containing keychains for all groups
	 * of which the user is a member.
	 *
	 * @param token token of the user requesting a keychain
	 * @return collection of keychains for all groups the member is in, null on error
	 */
	private Map<String, GroupKeychain> getUserKeychain(UserToken token)
	{
		String requester = token.getSubject();

		// Make sure the requesting user exists
		if (!userExists(requester))
			return null;

		// assemble keychains for all groups the user is in
		Map<String, GroupKeychain> keychain = new Hashtable<String, GroupKeychain>();
		for (String group : my_gs.userList.getUserGroups(requester)) {
			GroupKeychain gk = my_gs.groupKeychains.get(group);
			if (gk == null) {
				System.err.println("No keychain found for group '" + group + "'. Group owner will need to rekey the group.");
				continue;
			}
			keychain.put(group, gk);
		}

		return keychain;
	}

	/**
	 * Attempts to create a user using the permissions associated with the given token.
	 *
	 * @param newuser user to create
	 * @param token token of user requesting user creation
	 * @return user password if the new user is created, null otherwise
	 */
	private String createUser(String newuser, UserToken token)
	{
		String requester = token.getSubject();

		// Make sure the requester exists and is an admin
		if (!userExists(requester) || !isAdmin(requester))
			return null;

		// Check that a user with this name doesn't already exist
		if (my_gs.userList.checkUser(newuser)) {
			System.err.println("Cannot create new user '" + newuser + "'. A user with this name already exists.");
			return null;
		}

		// Create the new user
		String password = my_gs.userList.addUser(newuser);
		if (password != null) return password;

		return null;
	}

	/**
	 * Deletes a user if the requester is an ADMIN.
	 *
	 * @param user the user to delete
	 * @param token the token of the user requesting the deletion
	 * @return true if the deletion succeeded, false otherwise
	 */
	private boolean deleteUser(String user, UserToken token)
	{
		String requester = token.getSubject();

		// Make sure the requester exists and is an admin
		if (!userExists(requester) || !isAdmin(requester))
			return false;

		// Ensure that the user to delete exists
		if (!userExists(user)) {
			System.err.println("User '" + user + "' does not exist to be deleted.");
			return false;
		}

		// Delete the user
		my_gs.userList.deleteUser(user);

		return true;
	}

	/**
	 * Checks that a user exists, logging the result if not.
	 *
	 * @param username the user
	 * @return true if the user exists, false otherwise
	 */
	private boolean userExists(String username) {
		//Check if requester exists
		if(!my_gs.userList.checkUser(username))
		{
			System.err.println("User '" + username + "' does not exist -- permission denied.");
			return false;
		}

		return true;
	}

	/**
	 * Checks that a user is an admin, logging the result if not.
	 *
	 * @param username the user
	 * @return true if the user is in the group ADMIN, false otherwise
	 */
	private boolean isAdmin(String username) {
		if(!my_gs.userList.isAdmin(username))
		{
			System.err.println("User '" + username + "' is not an administrator -- permission denied.");
			return false;
		}

		return true;
	}

	/**
	 * Checks that the user owns the given group, logging the result if not.
	 *
	 * @param username the user
	 * @param group the group
	 * @return true if the user owns this group, false otherwise
	 */
	private boolean ownsGroup(String user, String group) {
		List<String> ownedGroups = my_gs.userList.getOwnedGroups(user);
		if(!ownedGroups.contains(group)) {
			System.err.println("User '" + user + "' is the not the owner of group '" + group + "' -- permission denied.");
			return false;
		}

		return true;
	}

	/**
	 * Verifies the signature on a token issued by this group server.
	 *
	 * @param token token issued by this file server
	 * @return true if the token is valid; false otherwise
	 */
	private boolean isValidToken(UserToken token) {
		if (!token.getIssuer().equals(GroupServer.SERVER_NAME)) {
			System.err.println("User at " + socket.getInetAddress() + " sent token issued by " + token.getIssuer());
			return false;
		}

		boolean valid = my_gs.verifySignature(token, rsaId.getPublicKey());
		if (!valid) {
			System.err.println("User at " + socket.getInetAddress() + " sent invalid token.");;
			return false;
		}

		return true;
	}
	
	public boolean checkValid(ArrayList<Object> message) {
		int index = message.size() - 1;
		if (threadNum.valid((Integer)message.get(index)) == false) {
			System.out.println("Warning: Invalid sequence number from group client!");
			return false;
		}
		else 
			return true;
		
	}
}
