package hussachai.osu.cs5243;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Standard Input/Output for reading value from console and printing value to console.
 * If there's no console available, the System.in will be used.
 * 
 * @author hussachai (http://www.siberhus.com) 
 *
 */
public class StdIO {
  
  private static Console console = System.console();
  private static BufferedReader reader = new BufferedReader(
      new InputStreamReader(System.in));
  
  /**
   * Read line from console
   * @return
   */
  public static String readLine(){
    return readLine(null);
  }
  
  /**
   * Read line from console with question text
   * @param message
   * @return
   */
  public static String readLine(String message){
    println(message);
    try{
      if(console != null){
        return console.readLine();
      }
      return reader.readLine().trim();
    }catch(IOException e){
      e.printStackTrace();
      return null;
    }
  }
  
  /**
   * Read password from console.
   * @return
   */
  public static String readPassword(){
    return readPassword(null);
  }
  
  /**
   * Read password from console
   * @param message
   * @return
   */
  public static String readPassword(String message){
    println(message);
    try{
      if(console != null){
        return new String(console.readPassword());
      }
      return reader.readLine().trim();
    }catch(IOException e){
      e.printStackTrace();
      return null;
    }
  }
  
  /**
   * Print message to console
   * @param message
   */
  public static void println(String message){
    if(message != null) System.out.print(message + " ");
  }
  
}
