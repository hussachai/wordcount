package hussachai.osu.cs5243;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

/**
 * 
 * THe security session will be created for single session
 * after the mutual HMAC verification has completed successfully.
 * 
 * @author hussachai (http://www.siberhus.com) 
 *
 */
public class SecuritySession {
  
  /**
   * Default iteration for password hashing
   */
  public static final int DEFAULT_ITERATION = 65536;
  
  /**
   * Default key length
   */
  public static final int DEFAULT_KEY_LENGTH = 192;
  
  /**
   * Use secure random to generate session ID
   */
  private SecureRandom random = new SecureRandom();
  
  /**
   * Secret key factory for PBKDF2 (Password-Based Key Derivation Function 2)
   * In this case, we use PBKDF2 with HMAC SHA1.
   */
  private SecretKeyFactory secretKeyFactory;
  
  /**
   * Shared secret key used for both encryption and keyed HMAC
   * as specified in specification. 
   */
  private SecretKey secretKey;
  
  private SecuritySession(){}
  
  /**
   * Factory method for Security Session
   * @param password
   * @param iterationCount
   * @param keyLength
   * @return
   * @throws GeneralSecurityException
   */
  public static SecuritySession create(String password,
      int iterationCount, int keyLength) throws GeneralSecurityException{
    /* Generate salt from SHA256 of the combination of password, iterationCount and keyLength */
    byte salt[] = sha256(password+"|"+iterationCount+"|"+keyLength);
    SecuritySession session = new SecuritySession();
    session.secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    /* Create key spec for Password-Based Encryption */
    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 
        iterationCount, keyLength);
    session.secretKey = session.secretKeyFactory.generateSecret(keySpec);
    return session;
  }
  
  /**
   * Factory method for Security Session using default iteration and default key length
   * @param password
   * @return
   * @throws GeneralSecurityException
   */
  public static SecuritySession create(String password) 
      throws GeneralSecurityException{
    
    return create(password, DEFAULT_ITERATION, DEFAULT_KEY_LENGTH);
  }
  
  /**
   * Encrypt message (Convert plain-text string to SecureMessage)
   * @param message
   * @return
   * @throws Exception
   */
  public SecureMessage encrypt(String message) throws Exception{
    /* Construct secret key for AES */
    SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
    /* Encrypt the message using AES in CBC mode with PKCS5 padding */
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secret);
    AlgorithmParameters params = cipher.getParameters();
    /* Get initialized vector */
    byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
    byte[] cipherBytes = cipher.doFinal(message.getBytes("UTF-8"));
    String hmac = generateHMAC(message);
    
    return new SecureMessage(hmac, ivBytes, cipherBytes);
  }
  
  /**
   * Decrypt message (Convert SecureMessage to plain-text string)
   * The HMAC is used for content verification and user authentication.
   *  
   * @param secureMessage
   * @return
   * @throws Exception
   */
  public String decrypt(SecureMessage secureMessage) throws Exception{
    /* Construct secret key for AES */
    SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    /* Decrypt using the shared secret key and IVs generated from encryption */
    cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(secureMessage.getIvBytes()));
    /* Decipher text and convert to UTF-8 encoding string */
    String decipherText = new String(cipher.doFinal(
        secureMessage.getCipherBytes()), "UTF-8");
    /* HMAC verification */
    String inputHMAC = secureMessage.getHMAC();
    String computedHMAC = generateHMAC(decipherText);
    if(!inputHMAC.equals(computedHMAC)){
      throw new RuntimeException("HMAC verification failed");
    }
    return decipherText;
  }
  
  /**
   * Generate keyed HMAC code using message.
   * @param message
   * @return
   * @throws Exception
   */
  public String generateHMAC(String message) throws Exception {
    /* Use SHA2 256bits for message digest */
    Mac hmacSha2 = Mac.getInstance("HmacSHA256");
    /* Create secret key for HMAC */
    SecretKey hmacKey = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
    hmacSha2.init(hmacKey);
    /* Encode the HMAC to Hex */
    return Hex.encodeHexString(hmacSha2.doFinal(message.getBytes("UTF-8")));
    
  }
  
  /**
   * Generate session ID securely.
   * @return
   */
  public String generateSessionID(){
    return new BigInteger(130, random).toString(32);
  }
  
  /**
   * 
   * @param password
   * @return
   * @throws NoSuchAlgorithmException
   */
  public static byte[] sha256(String password) throws NoSuchAlgorithmException {
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    byte[] passBytes = password.getBytes();
    byte[] passHash = sha256.digest(passBytes);
    return passHash;
  }
  
}
