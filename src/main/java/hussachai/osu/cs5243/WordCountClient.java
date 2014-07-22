package hussachai.osu.cs5243;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * The Word Count client
 * 
 * @author hussachai (http://www.siberhus.com) 
 *
 */
public class WordCountClient {
  
  public WordCountClient(){
    System.setProperty("javax.net.ssl.trustStore", "client/wordcount.pub");
    System.setProperty("javax.net.ssl.trustStorePassword", "pass123");
    
  }
  
  /**
   * 
   * @param host
   * @param port
   * @param username
   * @param password
   * @throws Exception
   */
  public void connect(String host, int port, String username, String password) throws Exception{
    
    System.out.println("Connecting to "+host+" on port: "+port);
    /* Create SSL Socket Factory */
    SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
    /* Open the SSL connection by creating SSL Socket */
    SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
    
    String response = null;
    
    try(
        BufferedReader reader = new BufferedReader(new InputStreamReader(
            sslSocket.getInputStream()));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
            sslSocket.getOutputStream()))){
      /* Begin Mutual Authentication ============== */
      writer.write(username + "\n");
      writer.flush();
      
      SecuritySession session = SecuritySession.create(password);
      /* Client reads server's nonce */
      String serverNonce = reader.readLine().trim();
      String serverNonceMAC = session.generateHMAC(serverNonce);
      /* Generate client nonce */
      String clientNonce = session.generateSessionID();
      /* Client returns HMAC(serverNonce) with clientNonce to server */
      writer.write(serverNonceMAC+"|"+clientNonce+"\n");
      writer.flush();
      /* Client reads MAC(clientNonce) */
      String clientNonceMAC = reader.readLine();
      if(clientNonceMAC == null || 
          !clientNonceMAC.trim().equals(session.generateHMAC(clientNonce))){
        throw new RuntimeException("HMAC verification failed");
      }
      /* End Mutual Authentication ============== */
      
      System.out.println("Type 'quit' or Ctrl+C to exit");
      
      while((response = reader.readLine()) != null) {
        /* De-serialize encrypted text to the POJO */
        SecureMessage secureMessage = SecureMessage.fromString(response);
        /* Decrypt message to string. */
        response = session.decrypt(secureMessage);
        
        System.out.println("Server > "+response);
        String input = StdIO.readLine("Client > sentence: ");
        if("quit".equalsIgnoreCase(input)){
          System.out.println("Bye :D");
          break;
        }
        /* Encrypt input string and convert to secure message format */
        secureMessage = session.encrypt(input);
        
        writer.write(secureMessage.toString() + '\n');
        writer.flush();
      }
      
      sslSocket.close();
    }
  }
  
  /**
   * 
   * @param args
   * @throws Exception
   */
  public static void main(String[] args) throws Exception{
    String host = "localhost";
    int port = 9999;
    if(args.length == 0){
      System.out.println("No argument entered.");
      System.out.println("Use default host = "+host+" and port = "+port);
    }
    try{
      if(args.length > 1){
        host = args[0];
        if(args.length >= 2){
          try{
            port = Integer.parseInt(args[1]);
          }catch(Exception e){ throw new RuntimeException("port must be integer"); }
        }
      }
      String username = StdIO.readLine("Please enter your name:");
      String password = StdIO.readPassword("Please enter your password:");
      new WordCountClient().connect(host, port, username, password);
    }catch(Exception e){
      System.out.println("Connection terminated!");
      System.err.println(e.getMessage());
    }
  }
  
}
