/**
 * Plaintext implementation of UserToken interface.
 */

import java.util.ArrayList;
import java.util.List;

public class Token implements UserToken
{
	static final long serialVersionUID = 8109439211099337851L;

	private String issuer;
	private String subject;
	private ArrayList<String> groups;
	private byte[] signature;
	private int serverPort;
	private String serverName;

	/**
	 * Constructor.
	 */
	public Token(String issuer, String subject, List<String> groups, int serverPort, String serverName)
	{
		this.issuer = issuer;
		this.subject = subject;
		this.groups = new ArrayList<String>(groups);
		this.signature = null;
		this.serverPort = serverPort;
		this.serverName = serverName;
	}

	public String getServerName() {
		return serverName;
	}
	
	public int getServerPort() {
		return serverPort;
	}
	public String getIssuer()
	{
		return issuer;
	}

	public String getSubject()
	{
		return subject;
	}

	public List<String> getGroups()
	{
		return groups;
	}

	public void setSignature(byte[] signature)
	{
		this.signature = signature;
	}

	public byte[] getSignature()
	{
		return signature;
	}
}
