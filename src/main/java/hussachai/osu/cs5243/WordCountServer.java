package hussachai.osu.cs5243;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.text.MessageFormat;
import java.util.Date;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;

/**
 * Word Count Server.
 * The server uses SSL for communication to prevent man in the middle attack.
 * When the SSL is compromised, the mutual HMAC verification with nonce is
 * the second wall. The message will be encrypted using AES and transmitted
 * with HMAC signature to prevent message modification.
 * 
 * This server can service multiple clients at the same time
 * 
 * @author hussachai (http://www.siberhus.com) 
 * 
 * 
 */
public class WordCountServer {
  
  private int port = 9999;
  
  private Config config;
  
  public WordCountServer(){
    /* Load configuration from file */
    config = ConfigFactory.parseFile(new File("server/server.conf"));
    this.port = config.getInt("server.port");
    
    /* Initialize the private key store and password*/
    System.setProperty("javax.net.ssl.keyStore", "server/wordcount.pem");
    System.setProperty("javax.net.ssl.keyStorePassword", 
        config.getString("keyStore.password"));
  }
  
  /**
   * Start the word count server
   * @throws Exception
   */
  public void start() throws Exception{
    /* Create SSL server socket factory using default configuration */
    SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory) 
        SSLServerSocketFactory.getDefault();
    /* Create SSL server socket on specified port */
    SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory
        .createServerSocket(port);
    System.out.println("Server started at "+new Date());
    /* Continuing wait for handling incoming connection */
    while(true){
      System.out.println("Waiting for next client...");
      SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
      System.out.println("Client: "+sslSocket.getInetAddress().getHostAddress()+
          " has established connection at "+new Date());
      /* Start new thread and service client request */
      new WordCountService(config, sslSocket).start();
    }
  }
  
  /**
   * Word count service worker thread
   * @author hussachai
   *
   */
  public static class WordCountService extends Thread{
    
    private boolean debug;
    private Config config;
    private SSLSocket sslSocket;
    
    public WordCountService(Config config, SSLSocket sslSocket){
      this.config = config;
      this.sslSocket = sslSocket;
      debug = config.getBoolean("server.debug");
    }
    
    @Override
    public void run(){
      
      String response = null;
      String username = null;
      try(
          BufferedReader reader = new BufferedReader(
              new InputStreamReader(sslSocket.getInputStream()));
          BufferedWriter writer = new BufferedWriter(
              new OutputStreamWriter(sslSocket.getOutputStream()))){
        
        /* Reads username from client */
        username = reader.readLine().trim();
        System.out.println("User: "+username+" is trying to authenticate");
        Config users = config.getConfig("users");
        /* Checks whether supplied username is in database or not */
        if(!users.hasPath(username)){
          /* If username is not in database, close connection */ 
          System.out.println("User: "+username+" not found.");
          writer.write("Sorry user not found!\n");writer.flush();
          closeSocket();
          return;
        }
        
        /* Create new security session for user */ 
        SecuritySession session = SecuritySession.create(config.getString("users."+username));
        /* Create session ID for authentication */
        String serverNonce = session.generateSessionID();
        /* Server sends a random nonce to client */
        debug("Server nonce: {0}", serverNonce);
        writer.write(serverNonce+"\n");
        writer.flush();
        /* Server reads the response containing HMAC(server's nonce) and client's nonce */
        response = reader.readLine().trim();
        int sep = response.indexOf("|");
        if(sep == -1 && response.length() < sep + 1){
          throw new RuntimeException("Incorrect format message");
        }
        String serverNonceMAC = response.substring(0, sep);
        debug("Client returned MAC of server nonce: {0} ", serverNonceMAC);
        String clientNonce = response.substring(sep + 1, response.length());
        debug("Recieved client[{0}] nonce: {1} ", username, clientNonce);
        /* Server checks whether client can create the correct HMAC for server's nonce */
        if(serverNonceMAC.equals(session.generateHMAC(serverNonce))){
          String clientNonceMAC = session.generateHMAC(clientNonce);
          debug("Sending MAC of client nonce to client[{0}]: {1}", 
              username, clientNonceMAC);
          writer.write(clientNonceMAC+"\n");
          writer.flush();
        }else{
          throw new RuntimeException("HMAC verification failed");
        }
        
        System.out.println("User: "+username+" has been authenticated successfully");
        
        String message = "Hello "+username+". Welcome to awesome word counter service.";
        SecureMessage secureMessage = session.encrypt(message);
        writer.write(secureMessage.toString()+"\n");
        writer.flush();
        
        while ((response = reader.readLine()) != null) {
          secureMessage = SecureMessage.fromString(response);
          debug("Received message from client[{0}]: {1}", username, 
              secureMessage.getCipherText());
          debug("HMAC: {0}", secureMessage.getHMAC());
          response = session.decrypt(secureMessage);
          debug("Decrypted message: " + response);
          int wordCount = response.split("\\s+").length;
          int charCount = response.length();
          
          message = "Words: "+wordCount+", Characters: "+charCount;
          debug("Encrypting message: {0}", message);
          secureMessage = session.encrypt(message);
          debug("Sending message to client[{0}]: {1}", username, secureMessage);
          writer.write(secureMessage.toString()+"\n");
          writer.flush();
        }
      }catch(Exception e){
        e.printStackTrace();
        System.out.println("Error: "+e.toString()+
            " occurs during the conversion of: "+username);
        closeSocket();
      }finally{
        closeSocket();
        System.out.println("Disconnected: "+username+" at "+new Date());
      }
    }
    
    /**
     * Close SSL socket
     */
    protected void closeSocket(){
      try {
        System.out.println("Ending connection of "+sslSocket.getInetAddress().getHostAddress());
        sslSocket.close();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    
    
    protected void debug(String message, Object... args){
      if(debug){
        System.out.println("DEBUG > " + MessageFormat.format(message, args));
      }
    }
  }
  
  /**
   * 
   * @param args
   * @throws Exception
   */
  public static void main(String[] args) throws Exception{
    new WordCountServer().start();
  }
  
}
