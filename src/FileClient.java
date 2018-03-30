/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyRep;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.ArrayList;
import java.lang.reflect.Array;

import javax.crypto.Cipher;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileClient extends Client implements FileClientInterface {

	private static final Provider bc = new BouncyCastleProvider();

	private SecretKey sessionIntegrityKey;

	private Map<InetAddress, PublicKey> trustedServers;
	private final String trustedFile = "TrustedFileServers.bin";
	private final String username;
	
	//initial sequence numbers
	private int threadNumStart;
	private static int clientNumStart = 1;
	
	private Sequence threadNum;
	private Sequence clientNum;
	
	/**
	 * Default constructor.
	 */
	public FileClient(String username)
	{
		this.username = username;
		loadTrustedServers();
	}

	/**
	 * Override Client.connect to enforce secure connection.
	 */
	public boolean connect(final String server, final int port) {
		boolean success;

		success = super.connect(server, port);
		if (!success)
			return false;

		success = secureConnection();
		if (!success) { // break down insecure connection
			disconnect();
			return false;
		}

		return true;
	}

	/**
	 * Serializes trusted server address - pubkey mappings to a file.
	 */
	private void saveTrustedServers()
	{
		if (trustedServers == null) {
			System.err.println("No trusted servers exist to be saved.");
			return;
		}

		try {
			ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(username + "-" + trustedFile));
			oos.writeObject(trustedServers);
		} catch (Exception e) {
			System.out.println("Failed to save trusted servers list: " + e.getMessage());
		}
	}

	/**
	 * Deserializes trusted server address - pubkey mappings from a file -- on failure
	 * initializes an empty map.
	 */
	@SuppressWarnings("unchecked")
	private void loadTrustedServers()
	{
		try {
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(username + "-" + trustedFile));
			trustedServers = (Map<InetAddress, PublicKey>) ois.readObject();
		} catch (Exception e) {
			System.out.println("Failed to save trusted servers list: " + e.getMessage());
			trustedServers = new HashMap<InetAddress, PublicKey>();
		}
	}

	/**
	 * Completes handshake with already-connected file server, establishing
	 * a shared session key to encrypt remainder of session traffic.
	 *
	 * At the end of this, all objects written to input and output of this
	 * Client instance will be encrypted before transmission.
	 *
	 * @param expectedPubKey the expected public key for this file server;
	 * allowed to be null if this is a new file server
	 */
	public boolean secureConnection() {
		SecureRandom random = new SecureRandom();
		byte[] rand1 = new byte[FileHandshake.RAND_SIZE];
		random.nextBytes(rand1); // fill rand1 with random bytes

		// Step 1: client sends handshake request & random number 1
		Envelope env = new Envelope("REQ_PUBKEY");
	    env.addObject(rand1);
		try {
			output.writeObject(env);
		} catch (Exception e) {
			System.err.println("Handshake with file server failed: unable to send REQ_PUBKEY.");
			return false;
		}

		// Step 2: server sends public key & random number 2
		PublicKey pubKey;
		byte[] rand2;
		try {
			env = (Envelope)input.readObject();
			byte[] encodedPubKey = (byte[]) env.getObjContents().get(0);
			KeyFactory keyfac = KeyFactory.getInstance("RSA");
			pubKey = keyfac.generatePublic(new X509EncodedKeySpec(encodedPubKey));
			rand2 = (byte[]) env.getObjContents().get(1);
		} catch (Exception e) {
			System.err.println("Handshake with file server failed: unable to read response to REQ_PUBKEY.");
			return false;
		}
		if (!env.getMessage().equals("PUBKEY")) {
			System.err.println("Handshake with file server failed: invalid response to REQ_PUBKEY.");
			return false;
		}

		// validate public key and format of server's random contribution
		PublicKey expectedPubKey = trustedServers.get(sock.getInetAddress());
		if (expectedPubKey == null) { // this is the first time connecting
			System.out.println("Fingerprint of file server public key:");
			System.out.println(RSAIdentity.generateFingerprint(pubKey));
			System.out.print("Connect to this server and save this public key? ");
			Scanner scan = new Scanner(System.in);
			String resp = scan.nextLine();
			if (!resp.equals("yes") && !resp.equals("y")) { // abort -- untrusted
				System.out.println("Aborting connection to untrusted server.");
				return false;
			} else { // save this trusted key for this server
				trustedServers.put(sock.getInetAddress(), pubKey);
				saveTrustedServers();
			}
		} else if (!pubKey.equals(expectedPubKey)) { // notify user that key has changed
			System.out.println("Server-provided public key does not match expected!");
			System.out.println("Expected fingerprint of file server public key:");
			System.out.println(RSAIdentity.generateFingerprint(expectedPubKey));
			System.out.println("Actual fingerprint of file server public key:");
			System.out.println(RSAIdentity.generateFingerprint(pubKey));
			System.out.print("Connect to this server and save this new public key? ");
			Scanner scan = new Scanner(System.in);
			String resp = scan.nextLine();
			if (!resp.equals("yes") && !resp.equals("y")) { // abort -- untrusted
				System.out.println("Aborting connection to untrusted server.");
				return false;
			} else { // save this trusted key for this server
				trustedServers.put(sock.getInetAddress(), pubKey);
				saveTrustedServers();
			}
		}
		if (rand2.length != FileHandshake.RAND_SIZE) {
			System.err.println("Handshake with file server failed: invalid length random byte array.");
			return false;
		}

		// Step 3: generate pre-master secret and send encrypted with server public key
		KeyGenerator keygen;
		try {
			keygen = KeyGenerator.getInstance(FileHandshake.HMAC_ALG, FileHandshake.CRYPTO_PROVIDER);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Handshake with file server failed: failed to load key gen algorithm " + FileHandshake.HMAC_ALG + ".");
			return false;
		}
		keygen.init(FileHandshake.PREMASTER_SIZE * 8); // * 8 to convert bytes to bits
		SecretKey premasterSecret = keygen.generateKey();

		// wrap the key with the server public key and send it
		try {
			Cipher rsaWrapper = Cipher.getInstance(FileHandshake.KEYWRAP_ALG, FileHandshake.CRYPTO_PROVIDER);
			rsaWrapper.init(Cipher.WRAP_MODE, pubKey);
			byte[] wrappedPremaster = rsaWrapper.wrap(premasterSecret);
			env = new Envelope("PREMASTER");
			env.addObject(wrappedPremaster);
			env.addObject((Integer)clientNumStart);
			clientNum = new Sequence(clientNumStart);
			output.writeObject(env);
		} catch (Exception e) {
			System.err.println("Handshake with file server failed: failed to send premaster secret.");
			return false;
		}

		// Step 3a: generate master session key according to RFC 5246, Section 5
		BigInteger seed = new BigInteger(rand1).add(new BigInteger(rand2));
		byte[] labelBytes = new String("master secret").getBytes(StandardCharsets.US_ASCII);
		SecretKey masterSecret = FileHandshake.expandKey(premasterSecret, seed.add(new BigInteger(labelBytes)), FileHandshake.MASTER_SIZE);

		// Step 3b: generate session integrity key
		labelBytes = new String("session integrity").getBytes(StandardCharsets.US_ASCII);
		sessionIntegrityKey = FileHandshake.expandKey(premasterSecret, seed.add(new BigInteger(labelBytes)), FileHandshake.INTEG_SIZE);

		// Step 4: establish encrypted channel using new shared secret
		try {
			// generate IV for cipher from rand1
			AlgorithmParameterSpec ivSpec = new IvParameterSpec(rand1, 0, 16);
			// wrap the socket input/output streams with a cipher
			Cipher outstreamCipher = Cipher.getInstance(FileHandshake.CIPHER_ALG);
			outstreamCipher.init(Cipher.ENCRYPT_MODE, masterSecret, ivSpec);
			CipherOutputStream cipherOS = new CipherOutputStream(sock.getOutputStream(), outstreamCipher);
			Cipher instreamCipher = Cipher.getInstance(FileHandshake.CIPHER_ALG);
			instreamCipher.init(Cipher.DECRYPT_MODE, masterSecret, ivSpec);
			CipherInputStream cipherIS = new CipherInputStream(sock.getInputStream(), instreamCipher);

			// reroute the client input/output streams through the new cipher streams
			output = new ObjectOutputStream(cipherOS);
			output.flush(); // push through ObjectStream headers
			input = new ObjectInputStream(cipherIS);
		} catch (Exception e) {
			System.err.println("Handshake with file server failed: unable to establish encrypted input/output streams.");
			System.err.println(e.getMessage());
			return false;
		}

		// step 4a: check for valid server response 
		try {
			env = (Envelope)input.readObject();
			if (env.getMessage().equals("OK"))
				System.out.println("Server successfully authenticated. Using encryption for all file server communications.");
			else
				throw new Exception();
				
			ArrayList<Object> temp = env.getObjContents();
			threadNumStart = (Integer)temp.get(0);
			threadNum = new Sequence(threadNumStart);
		} catch (Exception e) {
			System.err.println("Handshake with file server failed: invalid response from server.");
			return false;
		}

		return true;
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
			env.addObject(threadNum.getSequenceNum());
			EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
	    try {
			output.writeObject(env);
		    env = (Envelope)input.readObject();
				if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false) return false;
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token, Map<String, GroupKeychain> userKeychain) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}

				File file = new File(destFile);
			    try {


				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);

					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
						env.addObject(threadNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
					    output.writeObject(env);

					    env = (Envelope)input.readObject();
						if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false) return false;

						// first chunk contains decryption data
						if (!env.getMessage().equals("CHUNK")) {
							System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
							file.delete();
							return false;
						}

						byte[] chunk = (byte[])env.getObjContents().get(0);
						String group = (String)env.getObjContents().get(2);
						GroupKeychain groupKeychain = userKeychain.get(group);

						short phase = chunk[0];
						phase += (chunk[1] << 8);

						int ivLen = chunk[2];
						ivLen += (chunk[3] << 8);
						ivLen += (chunk[4] << 16);
						ivLen += (chunk[5] << 24);

						byte[] iv = new byte[ivLen];
						for (int i = 0; i < ivLen; i++) {
							iv[i] = chunk[6+i];
						}

						// check that we have the keys for this phase of the group
						if (phase > groupKeychain.getPhase()) {
							System.out.println("You do not have the decryption/integrity keys for this file!");
							env = new Envelope("CLIENT_ERROR"); // tell the server we failed
							env.addObject(threadNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
							output.writeObject(env);
							return false;
						}

						// prepare cipher and HMAC function
						Mac hmac;
						Cipher cipher;
						try {
							hmac = Mac.getInstance("HmacSHA256", bc);
							hmac.init(groupKeychain.getHmacKey(phase));
							IvParameterSpec ivSpec = new IvParameterSpec(iv);
							cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", bc);
							cipher.init(Cipher.DECRYPT_MODE, groupKeychain.getEncryptionKey(phase), ivSpec);

							// update hmac on this chunk
							hmac.update(chunk, 0, (Integer)env.getObjContents().get(1));
							// decrypt data portion of first chunk
							chunk = cipher.update(chunk, 6+ivLen, ((Integer)env.getObjContents().get(1))-(6+ivLen));
							if (chunk != null)
								fos.write(chunk);
						} catch (Exception e) {
							System.out.println("Error decrypting downloaded file!");
							System.out.println(e.getMessage());
							env = new Envelope("CLIENT_ERROR"); // tell the server we failed
							env.addObject(threadNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
							output.writeObject(env);
							return false;
						}


						System.out.printf(".");
						env = new Envelope("DOWNLOADF"); //Success
						env.addObject(threadNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
						output.writeObject(env);
						env = (Envelope)input.readObject();
						if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false) return false;
							
						while (env.getMessage().compareTo("CHUNK")==0) {
								chunk = (byte[])env.getObjContents().get(0);
								hmac.update(chunk, 0, (Integer)env.getObjContents().get(1));
								try {
									chunk = cipher.update(chunk, 0, (Integer)env.getObjContents().get(1));
								} catch (Exception e) {
									System.out.println("Error decrypting downloaded file!");
									System.out.println(e.getMessage());
									env = new Envelope("CLIENT_ERROR"); // tell the server we failed
									env.addObject(threadNum.getSequenceNum());
									EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
									output.writeObject(env);
									return false;
								}
								fos.write(chunk);
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								env.addObject(threadNum.getSequenceNum());
								EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
								output.writeObject(env);
								env = (Envelope)input.readObject();
								if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false) return false;
						}

					    if(env.getMessage().compareTo("HMAC")==0) {
							// write out remaining decrypted data
							try {
								chunk = cipher.doFinal();
								fos.write(chunk);
							} catch (Exception e) {
								System.out.print("Error finalizing decryption of downloaded file: ");
								System.out.println(e.getMessage());
								System.out.println("This means the file was corrupted on file server or downloaded with error!");
								env = new Envelope("CLIENT_ERROR"); // tell the server we failed
								env.addObject(threadNum.getSequenceNum());
								EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
								output.writeObject(env);
								return false;
							}

							// check that the calculated HMAC matches the given one
							byte[] storedHmac = (byte[])env.getObjContents().get(0);
							byte[] calculatedHmac = hmac.doFinal();
							// if they're not equal we have a problem
							if (storedHmac == null || !Arrays.equals(storedHmac, calculatedHmac)) {
								System.out.printf("The downloaded file was corrupted! Aborting.\n");
								// inform server of failure
								env = new Envelope("BAD_HMAC");
								env.addObject(threadNum.getSequenceNum());
								EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
								output.writeObject(env);
								// fail
								return false;
							}

					    	fos.close();
							System.out.printf("\nTransfer successful: file %s\n", sourceFile);
							env = new Envelope("OK"); //Success
							env.addObject(threadNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
							output.writeObject(env);
						}
						else {
							System.out.printf("Error reading file %s (%s): no checksum block\n", sourceFile, env.getMessage());
							env = new Envelope("NO_HMAC");
							env.addObject(threadNum.getSequenceNum());
							EnvelopeAuthority.appendHmac(env, sessionIntegrityKey);
							output.writeObject(env);
							file.delete();
							return false;
						}
				    }

				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }


			    } catch (IOException e1) {

			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;


				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 message.addObject(threadNum.getSequenceNum());
			 EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);
			 output.writeObject(message);

			 e = (Envelope)input.readObject();
			 if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) return null;

			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token, GroupKeychain keychain) {

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {

			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 message.addObject(threadNum.getSequenceNum());
			 EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);
			 output.writeObject(message);


			 FileInputStream fis = new FileInputStream(sourceFile);

			 env = (Envelope)input.readObject();
			 if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false) return false;

			 if(env.getMessage().equals("READY"))
			 {
				System.out.printf("Meta data upload successful\n");

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

			 // prepare cipher and HMAC function
			 Mac hmac = Mac.getInstance("HmacSHA256", bc);
			 hmac.init(keychain.getCurrentIntegrityKey());
			 Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", bc);
			 cipher.init(Cipher.ENCRYPT_MODE, keychain.getCurrentEncryptionKey());
			 byte[] iv = cipher.getIV();

			 // send file prefix byte denoting phase number of encryption/integrity keys & enc. IV
			 byte[] prefix = new byte[6 + iv.length]; // 2 bytes for phase, 4 for iv size, rest for iv
			 short phase = keychain.getPhase();
			 prefix[0] = (byte) phase;
			 prefix[1] = (byte) (phase >> 8);
			 prefix[2] = (byte) iv.length;
			 prefix[3] = (byte) (iv.length >> 8);
			 prefix[4] = (byte) (iv.length >> 16);
			 prefix[5] = (byte) (iv.length >> 24);
			 int i = 6;
			 for (byte b : iv) {
				 prefix[i] = iv[i-6];
				 i++;
			 }

			 // begin digest with prefix bytes
			 hmac.update(prefix);

			 // send prefix bytes
			 message = new Envelope("CHUNK");
			 message.addObject(prefix);
			 message.addObject(new Integer(prefix.length));
			 message.addObject(threadNum.getSequenceNum());
			 EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);
			 output.writeObject(message);

			 env = (Envelope)input.readObject();
			 if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false)
				 return false;

			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");

						// run chunk through encryption cipher
						buf = cipher.update(buf, 0, n);
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}

					// if the data to encrypt was smaller than block size, wait for the next portion
					// of the buffer, or to add padding below if necessary
					if (buf != null) {
						// update digest with encrypted chunk
						hmac.update(buf);

						message = new Envelope("CHUNK");
						message.addObject(buf);
						message.addObject(buf.length);
						message.addObject(threadNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);

						output.writeObject(message);


						env = (Envelope)input.readObject();
						if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false) return false;
					}
			 }
			 while (fis.available()>0);

			if (env.getMessage().compareTo("READY")!=0) {
				System.out.printf("Server error: %s\n", env.getMessage());
				return false;
			}

			 // complete encryption and send any trailing data
			 byte[] endChunk = cipher.doFinal();
			 if (endChunk.length > 0) {
				 hmac.update(endChunk);
				 message = new Envelope("CHUNK");
				 message.addObject(endChunk);
				 message.addObject(endChunk.length); // size of HMAC in bytes
				 message.addObject(threadNum.getSequenceNum());
				 EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);
				 output.writeObject(message);
				 env = (Envelope)input.readObject();
				 if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false)
					 return false;
				 if (env.getMessage().compareTo("READY")!=0) {
					System.out.printf("Server error: %s\n", env.getMessage());
				 	return false;
				 }
			 }

			 // send HMAC bytes
			 message = new Envelope("CHUNK");
			 message.addObject(hmac.doFinal());
			 message.addObject(new Integer(hmac.getMacLength())); // size of HMAC in bytes
			 message.addObject(threadNum.getSequenceNum());
			 EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);
			 output.writeObject(message);

			 env = (Envelope)input.readObject();
			 if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false)
				 return false;

			 if(env.getMessage().compareTo("READY")==0)
			 {
				message = new Envelope("EOF");
				message.addObject(threadNum.getSequenceNum());
				EnvelopeAuthority.appendHmac(message, sessionIntegrityKey);
				output.writeObject(message);

				env = (Envelope)input.readObject();
				if (checkValid(env.getObjContents()) == false || EnvelopeAuthority.verifyHmac(env, sessionIntegrityKey) == false) return false;
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {

					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }

			}
			 else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}
	
	public boolean checkValid(ArrayList<Object> response) {
		int index = response.size() - 1;
		if (clientNum.valid((Integer)response.get(index)) == false) {
			System.out.println("Warning: Invalid sequence number from file thread!");
			return false;
		}
		else 
			return true;
	}
}

