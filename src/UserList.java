/* This list represents the users on the server */
import java.util.*;
import java.security.MessageDigest;
import java.lang.Exception;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import java.security.Provider;

	public class UserList implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
		Provider bc = new BouncyCastleProvider();

		//store groups along with all users in the group
		private Hashtable<String, ArrayList<String>> groups = new Hashtable<String, ArrayList<String>>();

		//store the names of all users
		ArrayList<String> allUsers = new ArrayList<>();

		public synchronized String addUser(String username)
		{
			Security.addProvider(bc);
			//generate new user password. password will be of length 8
			char[] allChar = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

			//let's generate our random Strings
			//Strings will have a max length of 20
			Random num = new Random();
			StringBuilder passwordBuild = new StringBuilder();
			for (int i = 0; i < 8; i++) {
				int randomCharIndex = num.nextInt(allChar.length);
				passwordBuild.append(allChar[randomCharIndex]);
			}

			String password = passwordBuild.toString();

			byte[] passwordHash = null;
			try {
				MessageDigest hash = MessageDigest.getInstance("SHA-256", "BC");
				passwordHash = hash.digest(password.getBytes("UTF-8"));
			}
			catch (Exception e) {
				System.out.println(e);
			}

			User newUser = new User(passwordHash);
			list.put(username, newUser);
			allUsers.add(username);

			return password;
		}


		/**
		 * Deletes a user.
		 *
		 * @param user the user to delete
		 */
		public synchronized void deleteUser(String user)
		{
			// Remove the user from all groups in which she is a member
			for (String group : getUserGroups(user)) {
				groups.get(group).remove(user);
			}

			// Delete the user
			list.remove(user);
			allUsers.remove(user);
		}

		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		/**
		 * Returns whether a group with this name exists.
		 *
		 * @return true if a group with this name exists, false otherwise
		 */
		public synchronized boolean groupExists(String group) {
			return groups.containsKey(group);
		}

		/**
		 * Returns whether the user belongs to the ADMIN group.
		 *
		 * @return true if the user is in group ADMIN, false otherwise
		 */
		public synchronized boolean isAdmin(String username) {
			return list.get(username).getGroups().contains("ADMIN");
		}

		/**
		 * Returns a list of groups this user belongs to.
		 *
		 * @param username the user
		 * @return a list of groups this user belongs to
		 */
		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}

		/**
		 * Returns a list of groups that this user owns.
		 *
		 * @param username the user
		 * @return a list of groups owned by username
		 */
		public synchronized ArrayList<String> getOwnedGroups(String username)
		{
			return list.get(username).getOwnership();
		}

		/**
		 * Creates a new group.
		 *
		 * @param group the name of the group to be created
		 * @param owner the name of the user who owns the new group
		 */
		public synchronized void createGroup(String group, String owner)
		{
			// Create a new membership list with the owner in it
			ArrayList<String> members = new ArrayList<String>();
			members.add(owner);

			// Add the new group
			groups.put(group, members);

			// Add the new group to the owner's membership list
			list.get(owner).addGroup(group);

			// Add the new group to the owner's ownership list
			addOwnership(owner, group);
		}


		/**
		 * Deletes a group.
		 *
		 * @param group the group to delete
		 */
		public synchronized void deleteGroup(String group)
		{
			// Remove all users from this group
			for (String user : allUsers) {
				if (list.get(user).getGroups().contains(group))
					removeUserFromGroup(user, group);
			}

			// Delete the group
			groups.remove(group);
		}

		/**
		 * Adds a user to a group.
		 *
		 * If the user is already a member of this group, does nothing.
		 *
		 * @param user user to add
		 * @param group group to add the user to
		 */
		public synchronized void addUserToGroup(String user, String group) {
			// don't insert the user into the group if (s)he's already a member
			if (groups.get(group).contains(user))
					return;

			// Add the group to the user's membership list
			list.get(user).addGroup(group);

			// Add the user to the group
			groups.get(group).add(user);
		}

		/**
		 * Removes a user from a group.
		 *
		 * If the user is not a member of this group, does nothing.
		 *
		 * @param user user to remove
		 * @param group group to remove the user from
		 */
		public synchronized void removeUserFromGroup(String user, String group) {
			// Remove the group from the user's membership list
			list.get(user).removeGroup(group);

			// Remove the user from the group
			groups.get(group).remove(user);
		}

		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}

		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}

		/*
		*	@param groupname name of the group you want to list users for
		*	@return ArrayList<String> containing all the usernames of the users in a group
		*/
		public synchronized ArrayList<String> getGroupMembers(String groupname) {
			return groups.get(groupname);
		}
		
		public synchronized byte[] getUserPassword(String user) {
			return list.get(user).getPassword();
		}

	class User implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private byte[] passwordHash;

		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}

		public User(byte[] passwordHash)
		{
			this.passwordHash = passwordHash;
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}


		public ArrayList<String> getGroups()
		{
			return groups;
		}

		public ArrayList<String> getOwnership()
		{
			return ownership;
		}

		public byte[] getPassword()
		{
			return passwordHash;
		}

		public void addGroup(String group)
		{
			groups.add(group);
		}

		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}

		public void addOwnership(String group)
		{
			ownership.add(group);
		}

		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}

	}

}
