import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.Provider;

public abstract class Client {
	// protected so that sub-classes have access
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	/**
	 * Attempts to connect this client to the provided server, port.
	 *
	 * @return true if the connection succeeds, false otherwise
	 */
	public boolean connect(final String server, final int port) {
		Provider bc = new BouncyCastleProvider();
		Security.addProvider(bc);

		// Adapted from sample-client-server project
		try{
			// close any lingering connection (if there is one)
			this.disconnect();

			// create a new socket
			sock = new Socket(server, port);

			try {
				// Save I/O streams of newly connected socket
				output = new ObjectOutputStream(sock.getOutputStream());
				input = new ObjectInputStream(sock.getInputStream());

				return true;
			} catch (Exception e) {
				System.out.println("Could not connect to " + server + ":" + port + " -- connection refused.");
				return false;
			}
		}
		catch(Exception e){
			System.err.println("Error connecting to " + server + ", port " + port +":");
			System.err.println(e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	/**
	 * Returns whether this client is currently connected to a server.
	 *
	 * @return true if this client is connected to a server, false otherwise
	 */
	public boolean isConnected() {
		if (sock == null || sock.isClosed() || !sock.isConnected())
			return false;
		else
			return true;
	}

	/**
	 * Disconnects the Client if it is connected, closing open sockets and input/output streams.
	 */
	public void disconnect() {
		if (isConnected()) {
			try {
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);

				// close the current socket and its input/output streams
				sock.close();

				// clear instance variables
				output = null;
				input = null;
				sock = null;
			} catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
