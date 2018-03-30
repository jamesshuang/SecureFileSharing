/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;

public class GroupServer extends Server {

	public static final String SERVER_NAME = "ALPHA";
	public static final int SERVER_PORT = 8765;
	public UserList userList;
	private static RSAIdentity rsaId;

	private static final int maxFailedAttempts = 5; // blacklist ip after this many failed connection attempts
	private ExpiringCache clientBlacklist = new ExpiringCache(300000); // blacklist entries stay valid for 5 minutes

	public static final String KEYCHAINS_FILE = "GroupKeychains.bin";
	public Hashtable<String, GroupKeychain> groupKeychains;
	
	public UserListIdentity userListId;

	public GroupServer() {
		this(SERVER_PORT);
		userListId = new UserListIdentity();
	}

	public GroupServer(int _port) {
		super(_port, SERVER_NAME);
		
		userListId = new UserListIdentity();
		
		// set up RSA ID
		rsaId = new RSAIdentity();
		boolean success = rsaId.loadKeyPair(SERVER_NAME + ".keypair"); // attempt to load
		if (!success) {
			System.out.println("Generating an RSA keypair for this server...");

			if (!rsaId.generateKeyPair()) {
				System.err.println("Fatal error: cannot generate RSA keypair.");
				System.exit(1);
			}

			System.out.println("Done!");
			if (rsaId.storeKeyPair(SERVER_NAME + ".keypair"))
				System.out.println("Server keypair saved to disk.");
			if (rsaId.writePublicKeyFile(SERVER_NAME + ".pub"))
				System.out.println("Group Server public key saved to " + SERVER_NAME + ".pub -- share with File Server admins as needed.");
		}
		System.out.println("Successfully loaded RSA keypair.");
		System.out.println("Public key fingerprint:");
		System.out.println(RSAIdentity.generateFingerprint(rsaId.getPublicKey()));
	}

	@SuppressWarnings("unchecked")
	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			userList = userListId.load();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			String password = userList.addUser(username);
			System.out.println(username + "'s password: " + password);
			System.out.println("This password will never be shown again. Please do not lose");
			userList.createGroup("ADMIN", username);
			userListId.generateKey();
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(Exception e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		// attempt to load stored group keychains
		try
		{
			FileInputStream fis = new FileInputStream(KEYCHAINS_FILE);
			ObjectInputStream ois = new ObjectInputStream(fis);
			groupKeychains = (Hashtable<String, GroupKeychain>)ois.readObject();
		}
		catch(FileNotFoundException e)
		{
			// inform but do not automatically rekey files
			System.out.println(KEYCHAINS_FILE + " not found. Existing groups may need to be rekeyed.");
			groupKeychains = new Hashtable<String, GroupKeychain>();
		}
		catch(IOException e)
		{
			System.out.println("Error reading from " + KEYCHAINS_FILE);
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from " + KEYCHAINS_FILE);
			System.exit(-1);
		}

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		System.out.println("Group Server " + SERVER_NAME + " up and running.");

		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				if (shouldAcceptConnection(sock.getInetAddress().toString())) {
					thread = new GroupThread(sock, this, rsaId);
					thread.start();
				} else {
					System.out.println("Refusing connection with blacklisted IP " + sock.getInetAddress() + " for 5 minutes");
					sock.close();
				}
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

	/**
	 * Registers an IP for failing authentication.
	 */
	public void registerFailedConnectionAttempt(String sourceIp) {
		int currentCount = clientBlacklist.get(sourceIp) + 1;
		clientBlacklist.put(sourceIp, currentCount);
	}

	/**
	 * Returns true if the connection should be accepted,
	 * i.e., if the client is not black-listed.
	 */
	public boolean shouldAcceptConnection(String sourceIp) {
		return (clientBlacklist.get(sourceIp) < maxFailedAttempts);
	}
}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			// save userlist
			my_gs.userListId.save(my_gs.userList);

			// save group keychains
			outStream = new ObjectOutputStream(new FileOutputStream(GroupServer.KEYCHAINS_FILE));
			outStream.writeObject(my_gs.groupKeychains);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					my_gs.userListId.save(my_gs.userList);

					// save group keychains
					outStream = new ObjectOutputStream(new FileOutputStream(GroupServer.KEYCHAINS_FILE));
					outStream.writeObject(my_gs.groupKeychains);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
