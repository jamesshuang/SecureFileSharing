/**
 * Kubera.java
 *
 * Command-line interface for accessing group and file servers.
 *
 * This client can handle a single user at a time.
 *
 * Why Kubera? He's the Hindu Lord of Wealth (as in files, of course),
 * plus his name is similar to Kerberos. Right, now you see.
 *
 * CS 1653, Fall 2016
 *
 * @author Nathaniel Blake
 * @author James Huang
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.Provider;

public class Kubera {

	private static final GroupClient groupClient = new GroupClient();
	private static FileClient fileClient;
	private static final Scanner inputScanner = new Scanner(System.in);

	// store saved user information to this folder, including server address info
	private static final String DATA_DIR = ".kubera/";

	private static String username;
	private static UserToken userToken;
	private static Map<String, GroupKeychain> userKeychain;
	
	private static String serverName = null;
	private static int serverPort = 0;

	/**
	 * Sets up the main user input loop.
	 */
	public static void main(String args[]) {
		parseArgs(args);

		System.out.println("==== Hi, " + username + "! Welcome back to Kubera. ====");

		fileClient = new FileClient(username);

		// funnel user into token-getting path, since one is necessary for any future operations
		System.out.println("Let's get you a token...");
		int attempts = 1;
		boolean success = false;
		if (!handleGroupConnection()) {
				attempts++;
				if (attempts >= 2)
					return; // quit the app
				System.out.println("Let's give it another try.");
		}
		handleGroupSession();
	}

	/**
	 * Uses JOpt-Simple to parse command-line flags/arguments.
	 */
	private static void parseArgs(String args[]) {
		OptionParser parser = new OptionParser();
		parser.acceptsAll(Arrays.asList("u", "user"), "username for the Kubera session").withRequiredArg().required();
		parser.acceptsAll(Arrays.asList("h", "help"), "show this help").forHelp();

		OptionSet opts = parser.parse(args);

		// show usage information
		if (opts.has("h")) {
			try {
				System.out.println("Usage:");
				parser.printHelpOn(System.out);
			} catch (Exception e) { /* squash; we're about to exit regardless */ };
			System.exit(1);
		}

		// store username for this session
		username = (String) opts.valueOf("user");
	}

	/**
	 * Checks whether a Kubera application data folder exists.
	 *
	 * @return whether there is a Kubera data folder
	 */
	private static boolean dataDirExists() {
		return new File(DATA_DIR).exists();
	}

	/**
	 * Creates a directory for Kubera user data and configuration storage.
	 *
	 * @return true if the directory was successfully created; false otherwise
	 */
	private static boolean createDataDir() {
		File dataDir = new File(DATA_DIR);

		boolean success = dataDir.mkdir();
		if (!success) {
			System.err.println("Error: Could not create Kubera data directory at '" + DATA_DIR + "'.");
			return false;
		}

		return true;
	}

	/**
	 * Handle the interactive connection to a group server.
	 *
	 * TODO: store previous server connection details to facilitate future connections
	 *
	 * @return true if the connection was successful, false otherwise
	 */
	private static boolean handleGroupConnection() {
		System.out.println("Please enter the Group Server information.");
		System.out.print("Address: ");
		String serverName = inputScanner.nextLine().trim();
		System.out.print("Port: ");
		int port = Integer.parseInt(inputScanner.nextLine());

		boolean success = groupClient.connect(serverName, port);
		if (!success) {
			System.out.println("Failed to connected to the Group Server.");
			return false;
		}

		System.out.print("Please enter your user password: ");
		String password = inputScanner.nextLine().trim();
		success = groupClient.handshake(username, password);
		if (!success) {
			System.out.println("Failed to authenticate with server.");
			return false;
		}

		System.out.println("You are mutually authenticated with the Group Server. All further communications encrypted.");
		String[] cmd = {"get", "token", serverName, new Integer(port).toString()};
		groupCommandGet(cmd);
		return true;
	}

	/**
	 * Handle the interactive connection to a file server.
	 *
	 * TODO: store previous server connection details to facilitate future connections
	 *
	 * @return true if the connection was successful, false otherwise
	 */
	private static boolean handleFileConnection() {
		System.out.println("Please enter the File Server information.");
		System.out.print("Address: ");
		serverName = inputScanner.nextLine();
		System.out.print("Port: ");
		serverPort = Integer.parseInt(inputScanner.nextLine());
		boolean success = fileClient.connect(serverName, serverPort);
		if (!success) {
			System.out.println("Failed to connect to the File Server.");
			return false;
		}

		System.out.println("You are connected to the File Server.");
		return true;
	}

	/**
	 * User-interaction loop for connecting to and utilizing the group server.
	 */
	private static void handleGroupSession() {
		if (!groupClient.isConnected()) {
			boolean success = handleGroupConnection();
			if (!success)
				return;
		}

		System.out.println("Type 'help' at any time for a list of commands.");

		boolean proceed = true;
		do {
			// grab entire user command then split by spaces into words
			System.out.print("> ");
			String[] cmdTokens = inputScanner.nextLine().split(" ");

			switch (cmdTokens[0]) { // check the verb portion of command
				case "connect":
					generalCommandConnect(cmdTokens);
					break;
				case "exit":
					groupClient.disconnect();
					generalCommandExit();
					break; // unreachable, technically
				case "disconnect":
					groupClient.disconnect();
					System.out.println("Disconnected from group server.");
					proceed = false;
					break;
				case "help":
					printGroupCommands();
					break;
				case "get":
					groupCommandGet(cmdTokens);
					break;
				case "create":
					groupCommandCreate(cmdTokens);
					break;
				case "delete":
					groupCommandDelete(cmdTokens);
					break;
				case "rekey":
					groupCommandRekey(cmdTokens);
					break;
				case "list":
					groupCommandList(cmdTokens);
					break;
				case "add":
					groupCommandAdd(cmdTokens);
					break;
				case "remove":
					groupCommandRemove(cmdTokens);
					break;
				default:
					System.out.println("Invalid command. Type 'help' for a list of commands.");
					break;
			}
		} while (proceed);
	}

	/**
	 * Parses and executes a user command beginning with the 'get' verb,
	 * directed to the group server.
	 *
	 * The valid commands with this verb are
	 *
	 *   get token serverName serverPort
	 *   get keychain
	 *
	 * Which do not require special permissions except that the user exist.
	 */
	private static void groupCommandGet(String[] command) {
		if (!(
			(command.length == 4 && command[1].equals("token")) ||
			(command.length == 2 && command[1].equals("keychain")) 
			)) {
			System.out.println("Invalid format for 'get' command.");
			return;
		}
		
		// handle token fetch
		if (command[1].equals("token")) {
			// attempt to get a (new) token for the current user
			userToken = groupClient.getToken(username, command[2], Integer.parseInt(command[3]));
			if (userToken == null) {
				System.out.println("Error fetching token...");
				return;
			}

			System.out.println("Fetched a token.");
			System.out.println("Issuer: " + userToken.getIssuer());
			System.out.println("Subject: " + userToken.getSubject());
			System.out.println("Groups: " + userToken.getGroups());
			System.out.println("Destination Server: " + userToken.getServerName());
			System.out.println("Destination Port: " + userToken.getServerPort());
		} else { // handle keychain fetch
			if (userToken == null) {
				System.out.println("You need a token for this operation.");
				return;
			}
			userKeychain = groupClient.getUserKeychain(userToken);
			if (userKeychain == null) {
				System.out.println("Error fetching keychain...");
				return;
			}

			System.out.println("Fetched keychain with keys for groups: " + userKeychain.keySet());
		}
	}

	/**
	 * Parses and executes a user command beginning with the 'create' verb,
	 * directed to the group server.
	 *
	 * This command must follow one of the two following formats:
	 *
	 *   create user &lt;name&gt;
	 *   create group &lt;name&gt;
	 *
	 * Creating a new user requires the requesting user to be in the
	 * administrator group.
	 *
	 * @param command the tokenized user command
	 */
	private static void groupCommandCreate(String[] command) {
		if (command.length != 3) { // too few/many arguments
			System.out.println("Invalid format for 'create' command.");
		} else if (command[1].equals("group")) {
			// attempt to create a new group; command[2] is the new group name
			boolean success = groupClient.createGroup(command[2], userToken);

			if (success)
				System.out.println("Created group " + command[2] + ".");
			else
				System.out.println("Failed to create group " + command[2] + ".");
		} else if (command[1].equals("user")) {
			// attempt to create a new user with the name stored in command[2]
			String password = groupClient.createUser(command[2], userToken);

			if (password != null) {
				System.out.println("Created user " + command[2] + ".");
				System.out.println(command[2] + "'s password: " + password);
				System.out.println("This password will never be shown again. Please do not lose");
			}
			else
				System.out.println("Failed to create user " + command[2] + ".");
		} else { // create ____  command doesn't exist
			System.out.println("Invalid format for 'create' command.");
		}
	}

	/**
	 * Parses and executes a user command beginning with the 'delete' verb,
	 * directed to the group server.
	 *
	 * This command must follow one of the two following formats:
	 *
	 *   delete user &lt;name&gt;
	 *   delete group &lt;name&gt;
	 *
	 * Deleting a user requires the requesting user to be in the
	 * administrator group, while to delete a group, the user
	 * must own that group.
	 *
	 * @param command the tokenized user command
	 */
	private static void groupCommandDelete(String[] command) {
		if (command.length != 3) { // too few/many arguments
			System.out.println("Invalid format for 'delete' command.");
		} else if (command[1].equals("group")) {
			// attempt to delete the group; command[2] is group name
			boolean success = groupClient.deleteGroup(command[2], userToken);

			if (success)
				System.out.println("Deleted group " + command[2] + ".");
			else
				System.out.println("Failed to delete group " + command[2] + ".");
		} else if (command[1].equals("user")) {
			boolean success = groupClient.deleteUser(command[2], userToken);

			if (success)
				System.out.println("Deleted user " + command[2] + ".");
			else
				System.out.println("Failed to delete user " + command[2] + ".");
		} else { // create ___  command doesn't exist
			System.out.println("Invalid format for 'delete' command.");
		}
	}

	/**
	 * Parses and executes a user command beginning with the 'rekey' verb,
	 * directed to the group server.
	 *
	 * This command must follow the following format:
	 *
	 *   rekey group &lt;name&gt;
	 *
	 * Rekeying a group requires that the requester be the group owner.
	 *
	 * @param command the tokenized user command
	 */
	private static void groupCommandRekey(String[] command) {
		if (command.length != 3 || !command[1].equals("group")) {
			System.out.println("Invalid format for 'rekey' command.");
		} 

		// attempt to rekey the group; command[2] is group name
		boolean success = groupClient.rekeyGroup(command[2], userToken);

		if (success)
			System.out.println("Rekeyed group " + command[2] + ". Be sure to fetch an updated keychain.");
		else
			System.out.println("Failed to rekey group " + command[2] + ".");
	}

	/**
	 * Handles group server commands starting with verb 'list'.
	 *
	 * The only valid command of this form is
	 *
	 *   list group &lt;name&gt;
	 */
	private static void groupCommandList(String[] command) {
		if (command.length != 3 || !command[1].equals("group")) {
			System.out.println("Invalid format for 'list' command.");
			return;
		}

		List<String> members = groupClient.listMembers(command[2], userToken);
		if (members == null) {
			System.out.println("Failed to get member list for group " + command[2] + ".");
			return;
		}

		System.out.println("Members of group " + command[2] + ":");
		for (String member : members)
			System.out.println(member + " ");
	}

	/**
	 * Handles user commands beginning with the verb 'add',
	 * and directect to the group server.
	 *
	 * The valid command with this verb has the form
	 *
	 *   add &lt;user&gt; to &lt;group&gt;
	 *
	 * and requires that the requesting user be the owner of
	 * the group to modify.
	 */
	private static void groupCommandAdd(String[] command) {
		if (command.length != 4 || !command[2].equals("to")) {
			System.out.println("Invalid format for 'add' command.");
			return;
		}

		// command[1] is user to add to group, [3] is group
		String userToAdd = command[1];
		String targetGroup = command[3];
		boolean success = groupClient.addUserToGroup(userToAdd, targetGroup, userToken);

		if (success)
			System.out.println("Added " + userToAdd + " to group " + targetGroup + ".");
		else
			System.out.println("Failed to add " + userToAdd + " to group " + targetGroup + ".");
	}

	private static void groupCommandRemove(String[] command) {
		if (command.length != 4 || !command[2].equals("from")) {
			System.out.println("Invalid format for 'remove' command.");
			return;
		}

		// command[1] is user to remove from group, [3] is group
		String userToRemove = command[1];
		String targetGroup = command[3];
		boolean success = groupClient.deleteUserFromGroup(userToRemove, targetGroup, userToken);

		if (success)
			System.out.println("Removed " + userToRemove + " from group " + targetGroup + ".");
		else
			System.out.println("Failed to remove " + userToRemove + " from group " + targetGroup + ".");
	}

	/**
	 * User-interaction loop for connecting to and utilizing a file server.
	 */
	private static void handleFileSession() {
		if (!fileClient.isConnected()) {
			boolean success = handleFileConnection();
			if (!success)
				return;
		}

		System.out.println("Type 'help' at any time for a list of commands.");

		boolean proceed = true;
		do {
			// grab entire user command then split by spaces into words
			System.out.print("> ");
			String[] cmdTokens = inputScanner.nextLine().split(" ");

			switch (cmdTokens[0]) { // check the verb portion of command
				case "connect":
					generalCommandConnect(cmdTokens);
					break;
				case "exit":
					groupClient.disconnect();
					generalCommandExit();
					break; // unreachable, technically
				case "help":
					printFileCommands();
					break;
				case "disconnect":
					groupClient.disconnect();
					System.out.println("Disconnected from file server.");
					proceed = false;
					break;
				case "list":
					fileCommandList(cmdTokens);
					break;
				case "upload":
					fileCommandUpload(cmdTokens);
					break;
				case "download":
					fileCommandDownload(cmdTokens);
					break;
				case "delete":
					fileCommandDelete(cmdTokens);
					break;
				default:
					System.out.println("Invalid command. Type 'help' for a list of commands.");
					break;
			}
		} while (proceed);
		groupClient.disconnect();
	}

	/**
	 * Parses and executes a user command beginning with the verb 'list',
	 * directed to a file server.
	 *
	 * Valid commands have the form
	 *
	 *   list
	 *
	 */
	private static void fileCommandList(String[] command) {
		if (command.length != 1) {
			System.out.println("Invalid command. Perhaps you meant 'list'.");
			return;
		}

		// get and display the remote file listing
		List<String> files = fileClient.listFiles(userToken);

		if (files == null) {
			System.out.println("Error retrieving file listing from file server.");
			return;
		}

		System.out.println("Files stored on this file server:");
		for (String file : files)
			System.out.println(file);
		System.out.println(); // final blank line
	}

	/**
	 * Parses and executes a user command beginning with the verb 'upload',
	 * directed to a file server.
	 *
	 * Valid commands have the form
	 *
	 *   upload &lt;local filename&gt;
	 *
	 */
	private static void fileCommandUpload(String[] command) {
		if (command.length != 2) {
			System.out.println("Invalid command. Please only provide one file name per upload.");
			return;
		}

		// check that this file exists
		File upfile = new File(command[1]);
		if (!upfile.isFile()) {
			System.out.println("The file '" + command[1] + "' does not exist.");
			return;
		}

		// offer to rename the file before uploading
		System.out.println("What would you like to name the file on the server (default: " + command[1] + ")?");
		String upname = inputScanner.nextLine().trim().replaceAll("\\s", "_"); // take out spaces in new name
		if (upname.equals("")) // use default
			upname = command[1];

		// get the group to share the file with
		System.out.println("Which group would you like to share the file with?");
		String upgroup = "";
		do {
			System.out.println("Choices: " + userToken.getGroups());
			upgroup = inputScanner.nextLine();
		} while (!userToken.getGroups().contains(upgroup));

		// attempt to upload the file
		System.out.println("Uploading '" + command[1] + "' as '" + upname + "' to be shared with users in the group " + upgroup + ".");
		boolean success = fileClient.upload(command[1], upname, upgroup, userToken, userKeychain.get(upgroup));
		if (!success)
			System.out.println("Failed to upload.");
		else
			System.out.println("Success!");
	}

	/**
	 * Parses and executes a user command beginning with the verb 'download',
	 * directed to a file server.
	 *
	 * Valid commands have the form
	 *
	 *   download &lt;remote filename&gt; &lt;destination&gt;
	 */
	private static void fileCommandDownload(String[] command) {
		if (command.length != 3) {
			System.out.println("Invalid format for 'download' command. Type 'help' for a list of commands.");
			return;
		}

		boolean success = fileClient.download(command[1], command[2], userToken, userKeychain);
		if (!success) {
			System.out.println("Failed to download '" + command[1] + "' to '" + command[2] + "'.\nCheck that the file you want to download exists on the file server (type 'list') and that your destination file does not already exist.");
			return;
		}

		System.out.println("Downloaded '" + command[1] + "' from file server to '" + command[2] + "'.");
	}

	/**
	 * Parses and executes a user command beginning with the verb 'delete',
	 * directed to a file server.
	 *
	 * Valid commands have the form
	 *
	 *   delete &lt;remote filename&gt;
	 *
	 * and require no special privileges.
	 */
	private static void fileCommandDelete(String[] command) {
		if (command.length != 2) {
			System.out.println("Invalid format for 'delete' command. Type 'help' for a list of commands.");
			return;
		}

		boolean success = fileClient.delete(command[1], userToken);
		if (!success) {
			System.out.println("Failed to delete the file '" + command[1] + "'.\nCheck that this file exists on the file server (type 'list').");
			return;
		}

		System.out.println("Deleted '" + command[1] + "' from the file server.");
	}

	/**
	 * Handles commands starting with the verb 'connect' during any point
	 * in the user path.
	 *
	 * This command has the form
	 *
	 *   connect [group|file] &lt;server&gt; &lt;port&gt;
	 */
	private static void generalCommandConnect(String[] command) {
		if (command.length != 4) {
			System.out.println("Invalid format for 'connect' command. Type 'help' for a list of commands.");
			return;
		}

		boolean success;
		switch(command[1]) { // valid options are 'group' and 'file'
			case "group":
				// close a lingering connection
				if (groupClient.isConnected())
					groupClient.disconnect();

				success = groupClient.connect(command[2], Integer.parseInt(command[3]));
				if (!success) {
					System.out.println("Could not connect to Group Server at " + command[2] + ", port " + command[3] + ".");
					return;
				}

				System.out.print("Please enter your user password: ");
				String password = inputScanner.nextLine().trim();
				success = groupClient.handshake(username, password);
				if (!success) {
					System.out.println("Failed to authenticate with server.");
					return;
				}

				System.out.println("You are connected to the Group Server.");
				handleGroupSession();
				break;
			case "file":
				// close a lingering connection
				if (fileClient.isConnected())
					fileClient.disconnect();

				success = fileClient.connect(command[2], Integer.parseInt(command[3]));
				if (!success) {
					System.out.println("Could not connect to File Server at " + command[2] + ", port " + command[3] + ".");
					return;
				}

				System.out.println("You are connected to the File Server.");
				handleFileSession();
				break;
			default:
				System.out.println("Invalid format for 'connect' command. Type 'help' for a list of commands.");
				break;
		}
	}

	/**
	 * Closes any lingering connections and terminates the application.
	 */
	private static void generalCommandExit() {
		if (groupClient.isConnected())
			groupClient.disconnect();
		if (fileClient.isConnected())
			fileClient.disconnect();

		System.out.println("All server connections closed. Goodbye.");
		System.exit(0);
	}

	/**
	 * Prints generic commands that work in all contexts.
	 */
	private static void printGeneralCommands() {
		System.out.println("-- General Commands:\n"
				+ "connect [group|file] <server> <port>\n"
				+ "help\n"
				+ "exit\n");
	}

	/**
	 * Prints commands for use when connected to a file server.
	 */
	private static void printFileCommands() {
		printGeneralCommands();
		System.out.println("-- File Server Commands:\n"
				+ "disconnect\n"
				+ "list\n"
				+ "upload <local file>\n"
				+ "download <remote file> <destination>\n"
				+ "delete <remote file>\n");
	}

	/**
	 * Prints commands for use when connected to a file server.
	 *
	 * If the current user's token indicates membership in the ADMIN
	 * group, this list of commands includes administrative actions.
	 */
	private static void printGroupCommands() {
		printGeneralCommands();
		System.out.println("-- Group Server User Commands:\n"
				+ "disconnect\n"
				+ "get token <server name> <server port>\n"
				+ "get keychain\n"
				+ "create group <name>\n"
				+ "rekey group <name>\n"
				+ "delete group <name>\n"
				+ "list group <name>\n"
				+ "add <user> to <group>\n"
				+ "remove <user> from <group>\n");
		if (userToken != null && userToken.getGroups().contains("ADMIN")) {
			System.out.println("-- Group Server Admin Commands:\n"
					+ "create user <name>\n"
					+ "delete user <name>\n");
		}
	}
}
