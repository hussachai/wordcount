package hussachai.osu.cs5243;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import joptsimple.OptionParser;
import joptsimple.OptionSet;

/**
 * 
 * The main class for jar
 * 
 * @author hussachai
 *
 */
public class Main {
  
  private OptionParser parser = null;
  
  /**
   * Start the command parser and call the underlying service according to mode option
   * @param args
   * @throws Exception
   */
  public void start(String[] args) throws Exception {
    
    this.parser = new OptionParser(){
      {
        acceptsAll(Arrays.asList("m", "mode"), "mode can be either server or client").withRequiredArg();
        acceptsAll(Arrays.asList("h", "host"), "server's host address").withRequiredArg();
        acceptsAll(Arrays.asList("p", "port"), "server's port number").withRequiredArg();
        acceptsAll(Arrays.asList("?", "?" ), "show help" ).forHelp();
      }
    };
    OptionSet optionSet = null;
    try{
      optionSet = parser.parse(args);
    }catch(Exception e){
      printHelp(e.getMessage(), true);
    }
    if(!optionSet.has("m")){
      printHelp("mode option is required", true);
    }else{
      String mode = optionSet.valueOf("m").toString();
      if("server".equals(mode)){
        System.out.println("Starting wordcount server");
        WordCountServer.main(args);
      }else if("client".equals(mode)){
        List<String> clientArgs = new LinkedList<>();
        Object host = optionSet.valueOf("h");
        Object port = optionSet.valueOf("p");
        if(host != null) clientArgs.add(host.toString());
        if(port != null) clientArgs.add(port.toString());
        System.out.println("Starting wordcount client");
        WordCountClient.main(clientArgs.toArray(new String[0]));
      }else{
        printHelp("unknown mode: "+mode, true);
      }
    }
  }
  
  /**
   * Print help on screen
   * @param message
   * @param exit
   * @throws IOException
   */
  protected void printHelp(String message, boolean exit) throws IOException{
    System.out.println("============== HELP ================");
    System.out.println("Secure client-server word count service");
    System.out.println("Created by Hussachai Puripunpinyo");
    System.out.println("http://www.siberhus.com");
    System.out.println("Example: ");
    System.out.println("For server, please use: java wordcount.jar -m server");
    System.out.println("For client, please use: java wordcount.jar -m client -h localhost -p 9999");
    System.out.println("where -h and -p are optional and have the same default values as example");
    System.out.println("Make sure that the server directory is present when you use server mode");
    System.out.println("Also client directory must be present beside jar file when you use client mode");
    parser.printHelpOn(System.out);
    System.out.println("====================================");
    System.out.println(message);
    if(exit){
      System.exit(0);
    }
  }
  
  public static void main(String[] args) throws Exception {
    new Main().start(args);
  }
}
