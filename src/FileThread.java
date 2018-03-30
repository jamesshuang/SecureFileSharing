/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.lang.reflect.Array;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.net.InetAddress;


public class FileThread extends Thread
{
	private final FileServer parentFs;
	private final Socket socket;
	private ObjectInputStream input;
	private ObjectOutputStream output;
	private final RSAIdentity rsaId;
	private PublicKey groupServerPublicKey;
	private final InetAddress serverAddress;
	private final int serverPort;

	private SecretKey sessionIntegrityKey;
	
	//sequence numbers to protect message replay/reorder attacks
	private int threadNumStart = 1;
	private int clientNumStart;

	private Sequence clientNum;
	private Sequence threadNum;
	
	public FileThread(FileServer parent, Socket _socket, RSAIdentity rsaId, InetAddress serverAddress, int serverPort)
	{
		this.parentFs = parent;
		socket = _socket;
		this.rsaId = rsaId;
		this.serverAddress = serverAddress;
		this.serverPort = serverPort;
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			input = new ObjectInputStream(socket.getInputStream());
			output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
					if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) {
						response = new Envelope("INVALID_SEQUENCE_NUM");
						response.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
						output.writeObject(response);
						continue;
					}
					// check that the request has a valid size
					if(e.getObjContents().size() != 2)
					{
						response = new Envelope("FAIL-BADCONTENTS");
						response.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
						output.writeObject(response);
						continue; // handle the next request
					}

					// check for a token
					if (e.getObjContents().get(0) == null) {
						response = new Envelope("FAIL_BADTOKEN");
						response.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
						output.writeObject(response);
						continue; // handle the next request
					}

					// gather the files to which this user has access based on group membership
					UserToken token = (UserToken)e.getObjContents().get(0);
					if (!isValidToken(token)) {
						response = new Envelope("FAIL_BADTOKEN");
						response.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
						output.writeObject(response);
						proceed = false;
						System.out.println("Disconnecting from client at " + socket.getInetAddress() + " for using invalid token!");
						continue; // handle the next request
					}
					List<String> userFilepaths = new ArrayList<String>();
					for (String group : token.getGroups()) {
						for (ShareFile file : FileServer.fileList.getFilesForGroup(group)) {
							userFilepaths.add(file.getPath());
						}
					}

					// pass the list of files to the client
					response = new Envelope("OK");
					response.addObject(userFilepaths);
					response.addObject(clientNum.getSequenceNum());
					EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
					output.writeObject(response);
				}
				if(e.getMessage().equals("UPLOADF"))
				{
					if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) {
						response = new Envelope("INVALID_SEQUENCE_NUM");					
					}
					else if(e.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							if (!isValidToken(yourToken)) {
								response = new Envelope("FAIL_BADTOKEN");
								response.addObject(clientNum.getSequenceNum());
								EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
								output.writeObject(response);
								proceed = false;
								System.out.println("Disconnecting from client at " + socket.getInetAddress() + " for using invalid token!");
								continue; // handle the next request
							}

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File parentDir = new File("shared_files/" + group);
								parentDir.mkdirs();
								File file = new File("shared_files/"+group+"/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								response.addObject(clientNum.getSequenceNum());
								EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
								output.writeObject(response);

								e = (Envelope)input.readObject();
								boolean valid = true;
								if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) valid = false;
								while (e.getMessage().compareTo("CHUNK")==0 && valid) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									response.addObject(clientNum.getSequenceNum());
									EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
									output.writeObject(response);
									e = (Envelope)input.readObject();
									if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) {
										response = new Envelope("INVALID_SEQUENCE_NUM");
										valid = false;
									}
								}

								if(e.getMessage().compareTo("EOF")==0 && valid) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}
					response.addObject(clientNum.getSequenceNum());
					EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) {
						response = new Envelope("INVALID_SEQUENCE_NUM");
						response.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
						continue;
					}
					
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if (!isValidToken(t)) {
						response = new Envelope("FAIL_BADTOKEN");
						response.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
						output.writeObject(response);
						System.out.println("Disconnecting from client at " + socket.getInetAddress() + " for using invalid token!");
						proceed = false;
						continue; // handle the next request
					}
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						e.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(e, sessionIntegrityKey);
						output.writeObject(e);
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						e.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(e, sessionIntegrityKey);
						output.writeObject(e);
					}
					else {

						try
						{
							File f= new File("shared_files/"+sf.getGroup()+"/_"+remotePath.replace('/', '_'));
							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_NOTONDISK");
								e.addObject(clientNum.getSequenceNum());
								EnvelopeAuthority.appendHmac(e, sessionIntegrityKey);
								output.writeObject(e);

							}
							else {
								FileInputStream fis = new FileInputStream(f);
								do {
									byte[] buf = new byte[4096];
									if (e.getMessage().compareTo("DOWNLOADF")!=0) {
										System.out.printf("Server error: %s\n", e.getMessage());
										break;
									}

									int n;
									if (fis.available() < buf.length) {
										if (fis.available() <= 32) // we've reached the HMAC
											break;
										// read all but trailing 256-bit HMAC
										n = fis.available() - 32;
										n = fis.read(buf, 0, n); //can throw an IOException
									} else {
										n = fis.read(buf);
									}
									if (n > 0) {
										System.out.printf(".");

										e = new Envelope("CHUNK");
										e.addObject(buf);
										e.addObject(new Integer(n));
										e.addObject(sf.getGroup()); // send group the file belongs to
										e.addObject(clientNum.getSequenceNum());
										EnvelopeAuthority.appendHmac(e, sessionIntegrityKey);

										output.writeObject(e);

										e = (Envelope)input.readObject();
										if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) {
											break;
										}
									} else if (n < 0) {
										System.out.println("Read error");
									}

								}
								while (fis.available()>0);

								// send hmac trailer
								byte[] hmac = new byte[32];
								fis.read(hmac);
								fis.close();
								e = new Envelope("HMAC");
								e.addObject(hmac);
								e.addObject(clientNum.getSequenceNum());
								EnvelopeAuthority.appendHmac(e, sessionIntegrityKey);
								System.out.println(":");
								output.writeObject(e);

								e = (Envelope)input.readObject();
								if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) {
									break;
								}

								//If server indicates success, return the member list
								if(e.getMessage().compareTo("OK")==0)
								{	
									System.out.printf("File data upload successful\n");
								}
								else {
									System.out.printf("Upload failed: %s\n", e.getMessage());
								}
							}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					if (checkValid(e.getObjContents()) == false || EnvelopeAuthority.verifyHmac(e, sessionIntegrityKey) == false) {
						response = new Envelope("INVALID_SEQUENCE_NUM");
						output.writeObject(response);
						continue;
					}
					
					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if (!isValidToken(t)) {
						response = new Envelope("FAIL_BADTOKEN");
						response.addObject(clientNum.getSequenceNum());
						EnvelopeAuthority.appendHmac(response, sessionIntegrityKey);
						output.writeObject(response);
						proceed = false;
						System.out.println("Disconnecting from client at " + socket.getInetAddress() + " for using invalid token!");
						continue; // handle the next request
					}
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_files/"+sf.getGroup()+"/_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					e.addObject(clientNum.getSequenceNum());
					EnvelopeAuthority.appendHmac(e, sessionIntegrityKey);
					output.writeObject(e);

				}
				else if(e.getMessage().equals("REQ_PUBKEY"))
				{
					boolean success = establishSecureConnection(e);
					if (!success)
						System.err.println("Failed to establish secure connection with client " + socket.getInetAddress() + ".");
					else
						System.out.println("Established secure connection with client "  + socket.getInetAddress() + ".");
				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					proceed = false;
				}
			} while(proceed);
			socket.close();
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	/**
	 * Completes the File Server end of the authentication/encryption-setup handshake.
	 */
	private boolean establishSecureConnection(Envelope req)
	{
		SecureRandom random = new SecureRandom();

		// Step 1: receive REQ_PUBKEY and rand1 from client
		byte[] rand1 = (byte[]) req.getObjContents().get(0);
		if (rand1.length != FileHandshake.RAND_SIZE) {
			System.err.println("Handshake with file client failed: invalid random value received.");
			return false;
		}

		// Step 2: send public key and rand2 to client
		byte[] rand2 = new byte[FileHandshake.RAND_SIZE];
		random.nextBytes(rand2);

		// wrap public key in KeyRep and send it
		Key pubkey = rsaId.getPublicKey();
		byte[] encKey = pubkey.getEncoded();
		Envelope env = new Envelope("PUBKEY");
		env.addObject(encKey);
		env.addObject(rand2);

		try {
			output.writeObject(env);
		} catch (Exception e) {
			System.err.println("Handshake with file client failed: unable to send PUBKEY.");
			return false;
		}

		// Step 3: receive and unwrap premaster secret key using private key
		byte[] wrappedPremaster;
		Key premaster;
		try { // try to receive the premaster secret
			env = (Envelope) input.readObject();
			if (!env.getMessage().equals("PREMASTER"))
				throw new Exception();
			wrappedPremaster = (byte[]) env.getObjContents().get(0);
			clientNumStart = (Integer)env.getObjContents().get(1);
			clientNum = new Sequence(clientNumStart);
		} catch (Exception e) {
			System.err.println("Handshake with file client failed: did not receive proper premaster secret.");
			return false;
		}
		try { // try to unwrap the premaster secret
			Cipher rsaUnwrapper = Cipher.getInstance(FileHandshake.KEYWRAP_ALG, FileHandshake.CRYPTO_PROVIDER);
			rsaUnwrapper.init(Cipher.UNWRAP_MODE, rsaId.getPrivateKey());
			premaster = rsaUnwrapper.unwrap(wrappedPremaster, FileHandshake.HMAC_ALG, Cipher.SECRET_KEY);
		} catch (Exception e) {
			System.err.println("Handshake with file server failed: failed to send premaster secret.");
			return false;
		}

		// Step 3a: generate master session key according to RFC 5246, Section 5
		BigInteger seed = new BigInteger(rand1).add(new BigInteger(rand2));
		byte[] labelBytes = new String("master secret").getBytes(StandardCharsets.US_ASCII);
		SecretKey masterSecret = FileHandshake.expandKey(premaster, seed.add(new BigInteger(labelBytes)), FileHandshake.MASTER_SIZE);

		// Step 3b: generate session integrity key
		labelBytes = new String("session integrity").getBytes(StandardCharsets.US_ASCII);
		sessionIntegrityKey = FileHandshake.expandKey(premaster, seed.add(new BigInteger(labelBytes)), FileHandshake.INTEG_SIZE);

		// Step 4: establish encrypted channel using new shared secret
		try {
			// generate IV for cipher from rand1
			AlgorithmParameterSpec ivSpec = new IvParameterSpec(rand1, 0, 16);

			// wrap the socket input/output streams with a cipher
			Cipher outstreamCipher = Cipher.getInstance(FileHandshake.CIPHER_ALG);
			outstreamCipher.init(Cipher.ENCRYPT_MODE, masterSecret, ivSpec);
			CipherOutputStream cipherOS = new CipherOutputStream(socket.getOutputStream(), outstreamCipher);
			Cipher instreamCipher = Cipher.getInstance(FileHandshake.CIPHER_ALG);
			instreamCipher.init(Cipher.DECRYPT_MODE, masterSecret, ivSpec);
			CipherInputStream cipherIS = new CipherInputStream(socket.getInputStream(), instreamCipher);

			// reroute the client input/output streams through the new cipher streams
			output = new ObjectOutputStream(cipherOS);
			output.flush(); // push through ObjectStream headers
			input = new ObjectInputStream(cipherIS);
		} catch (Exception e) {
			System.err.println("Handshake with file client failed: unable to establish encrypted input/output streams.");
			System.err.println(e.getMessage());
			return false;
		}

		// step 4a: send confirmation message
		try {
			env = new Envelope("OK");
			env.addObject((Integer)threadNumStart);
			threadNum = new Sequence(threadNumStart);
			output.writeObject(env);
		} catch (Exception e) {
			System.err.println("Handshake with file client failed: unable to send success message.");
			return false;
		}

		return true;
	}


	/**
	 * Checks whether a token is valid, namely, whether
	 * the file server can verify the signature on the
	 * token using a Group Server public key on file.
	 *
	 * @param token the token to verify
	 * @return true if the token is valid; false if not,
	 * or if no public key is available to check the
	 * signature
	 */
	private boolean isValidToken(UserToken token) {
		if (groupServerPublicKey != null) {
			boolean verify = parentFs.verifySignature(token, groupServerPublicKey);
			String name = token.getServerName();
			int port = token.getServerPort();
			if (verify != true || serverPort != port || !parentFs.hostname.equals(name)) {
				return false;
			}
			else return true;
		}

		// otherwise, we'll need to load the GS pub key from a file
		String issuer = token.getIssuer();
		groupServerPublicKey = RSAIdentity.parsePublicKeyFile(issuer + ".pub");
		if (groupServerPublicKey == null) {
			System.out.println("Error: No " + issuer + " Group Server public key available to verify token signature!");
			return false;
		}
		System.out.println("Loaded Group Server public key from " + issuer + ".pub.");
		boolean verify = parentFs.verifySignature(token, groupServerPublicKey);
		String name = token.getServerName();
		int port = token.getServerPort();
		if (verify != true || serverPort != port || !parentFs.hostname.equals(name)) {
			return false;
		}
		else return true;
	}
	
	public boolean checkValid(ArrayList<Object> message) {
		int index = message.size() - 1;
		if (threadNum.valid((Integer)message.get(index)) == false) {
			System.out.println("Warning: Invalid sequence number from file client!");
			return false;
		}
		else 
			return true;
		
	}
}
