/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public class FileServer extends Server {

	public static final String SERVER_NAME = "FilePile";
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	public static RSAIdentity rsaId;

	public String hostname;

	public FileServer() {
		this(SERVER_PORT);
	}

	public FileServer(int _port) {
		super(_port, SERVER_NAME);

		// try to determine host name (for connecting users to use as token dest)
		try {
			hostname = InetAddress.getLocalHost().getHostName();
			System.out.println("Server host name: " + hostname);
		} catch (Exception e) {
			hostname = FileServer.SERVER_NAME;
			System.out.println("Could not find hostname... Defaulting to " + FileServer.SERVER_NAME);
		}

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
			rsaId.storeKeyPair(SERVER_NAME + ".keypair");
			System.out.println("Server keypair saved to disk.");
		}
		System.out.println("Successfully loaded RSA keypair.");
		System.out.println("Public key fingerprint:");
		System.out.println(RSAIdentity.generateFingerprint(rsaId.getPublicKey()));
	}

	public void start() {
		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");

			fileList = new FileList();

		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

		File file = new File("shared_files");
		 if (file.mkdir()) {
			 System.out.println("Created new shared_files directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found shared_files directory");
		 }
		 else {
			 System.out.println("Error creating shared_files directory");
		 }

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();


		boolean running = true;

		try
		{
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(running)
			{
				sock = serverSock.accept();
				thread = new FileThread(this, sock, rsaId, sock.getInetAddress(), sock.getLocalPort());
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
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
