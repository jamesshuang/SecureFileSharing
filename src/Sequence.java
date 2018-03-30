/*
 * Helper class to get track of sequence numbers
 */
public class Sequence {
  private int sequenceNum;
  
  /**
   * Constructor
   */
  public Sequence(int sequenceNum) {
    this.sequenceNum = sequenceNum;
  }
  
  /*
   * Method used to check validity of sequence number that is received
   *
   * @return true if sequence number is valid, false otherwise
   */
  public boolean valid(int messageNum) {
    if ((messageNum - sequenceNum) == 1) {
      sequenceNum++;
      return true;
    }
    else return false;
  }
  
  /*
   * Method used to retrieve sequence number for outgoing messages.
   * 
   * @return the sequence number incremented by one
   */
  public Integer getSequenceNum() {
    return ++sequenceNum;
  }
  
}