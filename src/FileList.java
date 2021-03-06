/* T
 * his list represents the files on the server */
import java.util.*;


	public class FileList implements java.io.Serializable {

	/*Serializable so it can be stored in a file for persistence */
	private static final long serialVersionUID = -8911161283900260136L;
	private ArrayList<ShareFile> list;

	public FileList()
	{
		list = new ArrayList<ShareFile>();
	}

	public synchronized void addFile(String owner, String group, String path)
	{
		ShareFile newFile = new ShareFile(owner, group, path);
		list.add(newFile);
	}

	public synchronized void removeFile(String path)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getPath().compareTo(path)==0) {
				list.remove(i);
			}
		}
	}

	public synchronized boolean checkFile(String path)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getPath().compareTo(path)==0) {
				return true;
			}
		}
		return false;
	}

	public synchronized ArrayList<ShareFile> getFiles()
	{
		Collections.sort(list);
		return list;
	}

	public synchronized ShareFile getFile(String path)
	{
		for (int i = 0; i < list.size(); i++) {
			if (list.get(i).getPath().compareTo(path)==0) {
				return list.get(i);
			}
		}
		return null;
	}

	/**
	 * Returns a list of files accessible to users in a specified group.
	 * @param group name of group whose files are being requested
	 * @return all files accessible to a member of the specified group
	 */
	public synchronized List<ShareFile> getFilesForGroup(String group)
	{
		List<ShareFile> groupFiles = new ArrayList<ShareFile>();
		for (ShareFile file : list) {
			if (group.equals(file.getGroup()))
				groupFiles.add(file);
		}
		Collections.sort(groupFiles);
		return groupFiles;
	}
}
