
import java.util.List;

/**
 * A simple interface to the token data structure that will be
 * returned by a group server.  
 *
 * You will need to develop a class that implements this interface so
 * that your code can interface with the tokens created by your group
 * server.
 *
 */
public interface UserToken extends java.io.Serializable
{
    /**
     * This method returns the server name of the file server
     * the user is trying to connect to
     */   
    public String getServerName();
    
    /*
     * This method returns the port number of the
     * file server that the user is trying
     * to connect to
     */
    public int getServerPort();
    
    /**
     * This method should return a string describing the issuer of
     * this token.  This string identifies the group server that
     * created this token.  For instance, if "Alice" requests a token
     * from the group server "Server1", this method will return the
     * string "Server1".
     *
     * @return The issuer of this token
     *
     */
    public String getIssuer();


    /**
     * This method should return a string indicating the name of the
     * subject of the token.  For instance, if "Alice" requests a
     * token from the group server "Server1", this method will return
     * the string "Alice".
     *
     * @return The subject of this token
     *
     */
    public String getSubject();


    /**
     * This method extracts the list of groups that the owner of this
     * token has access to.  If "Alice" is a member of the groups "G1"
     * and "G2" defined at the group server "Server1", this method
     * will return ["G1", "G2"].
     *
     * @return The list of group memberships encoded in this token
     *
     */
    public List<String> getGroups();

	/**
	 * This method returns the byte representation of the signature
	 * attached to the token, if it has been signed.
	 */
	public byte[] getSignature();

	/**
	 * This method allows for assigning a signature to the token, for
	 * instance to be used by implementors of the TokenAuthority interface.
	 */
	public void setSignature(byte[] signature);

}   //-- end interface UserToken
