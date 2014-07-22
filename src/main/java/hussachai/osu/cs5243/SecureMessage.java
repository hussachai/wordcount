package hussachai.osu.cs5243;

import org.apache.commons.codec.binary.Base64;

/**
 * The secure message object
 * 
 * @author hussachai (http://www.siberhus.com) 
 *
 */
public class SecureMessage {
  
  /**
   * HMAC (SHA)
   */
  private String hmac;
  
  /**
   * Ciphers
   */
  private byte[] cipherBytes;
  
  /**
   * Initial Vectors
   */
  private byte[] ivBytes;
  
  public SecureMessage(String hmac, byte[] ivBytes, byte[] cipherBytes){
    this.hmac = hmac;
    this.ivBytes = ivBytes;
    this.cipherBytes = cipherBytes;
  }
  
  /**
   * HMAC|IV|CIPHER
   */
  @Override
  public String toString(){
    return hmac + "|" + Base64.encodeBase64String(ivBytes) 
        + "|" + getCipherText();
  }
  
  /**
   * Parse string to SecureMessage format
   * HMAC|IV|CIPHER
   * @param string
   * @return
   */
  public static SecureMessage fromString(String string){
    if(string == null) return null;
    string = string.trim();
    int sep = string.indexOf("|");
    if(sep == -1 && string.length() < sep + 1){
      throw new RuntimeException("Incorrect format message");
    }
    String hmac = string.substring(0, sep);
    string = string.substring(sep + 1, string.length());
    sep = string.indexOf("|");
    if(sep == -1 && string.length() < sep + 1){
      throw new RuntimeException("Incorrect format message");
    }
    String ivText = string.substring(0, sep);
    String cipherText = string.substring(sep + 1, string.length());
    return new SecureMessage(hmac, Base64.decodeBase64(ivText), 
        Base64.decodeBase64(cipherText));
  }
  
  public String getHMAC(){
    return hmac;
  }
  
  public byte[] getCipherBytes(){
    return cipherBytes;
  }
  
  public String getCipherText(){
    return Base64.encodeBase64String(cipherBytes);
  }
  
  public byte[] getIvBytes(){
    return ivBytes;
  }
}
