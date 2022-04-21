//package main;
// 1. Open a socket.
// 2. Open an input stream and output stream to the socket.
// 3. Read from and write to the stream according to the server's protocol.
// 4. Close the streams.
// 5. Close the socket.

import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
/**
 * When a client connects the server spawns a thread to handle the client.
 * This way the server can handle multiple clients at the same time.
 *
 * This keyword should be used in setters, passing the object as an argument,
 * and to call alternate constructors (a constructor with a different set of
 * arguments.
 */

// Runnable is implemented on a class whose instances will be executed by a thread.
public class ClientHandler implements Runnable {

    // Array list of all the threads handling clients so each message can be sent to the client the thread is handling.
    public static HashMap<ClientHandler,Double> clientHandlers = new HashMap<>();
    // Id that will increment with each new client.
    int pub = 23;
    int g =   9 	 ;
    // Socket for a connection, buffer reader and writer for receiving and sending data respectively.
    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private static byte[] key;
    private final int KEY_SIZE = 128;
    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;
    private String clientUsername;
    static Key secretKey;
    double B,A,BDash;
    String bstring,Astring;
    Random rn = new Random();
    // Creating the client handler from the socket the server passes.
    public ClientHandler(Socket socket) {
        try {
            this.socket = socket;
            int privKey=0;
			try {
				privKey = rn.nextInt(12 - 1 + 1) + 4;
			
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
   System.out.println(privKey);
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.bufferedWriter= new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            // When a client connects their username is sent.
            this.clientUsername = bufferedReader.readLine();
            
            broadcastMessage("SERVER: " + clientUsername + " has entered the chat!");
            B = ((Math.pow(g, privKey)) % pub);
            bstring=Double.toString(B);
            this.bufferedWriter.write("/"+bstring);
            this.bufferedWriter.newLine();
            this.bufferedWriter.flush();
            String input=bufferedReader.readLine();
            System.out.println(input);
            Astring=input.split("/")[1];
            A=Double.parseDouble(Astring);
            BDash = ((Math.pow(A, privKey)) % pub);
            System.out.println("Symmetric Key:  "+BDash);
            clientHandlers.put(this,BDash);
        } catch (IOException e) {
            // Close everything more gracefully.
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    ClientHandler check(String user) {
    	for (ClientHandler clientHandler : clientHandlers.keySet()) {
 
    		System.out.println("name:   "+clientHandler.clientUsername);
                if (clientHandler.clientUsername.equals(clientUsername)) {
                    System.out.println("name:   "+clientHandler.clientUsername);
    
                    	return(clientHandler);
                }
    
    	}
        return (null);   }
    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
    public static String encrypt(final String strToEncrypt, final String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
    public static String decrypt(final String strToDecrypt, final String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
          
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder()
                    .decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
    public static void setKey(final String myKey) {
        MessageDigest s = null;
        try {
            key = myKey.getBytes("UTF-8");
            s = MessageDigest.getInstance("SHA-1");
            key = s.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (Exception e) {
            ((Throwable) e).printStackTrace();
        }
    }

    @Override
    public void run() {
        String messageFromClient;
        String Decrypted;

        while (socket.isConnected()) {
            
        	try {
   
                messageFromClient = bufferedReader.readLine();
               System.out.println("before decryption from client :  "+messageFromClient);
                Decrypted=decrypt(messageFromClient,Double.toString(clientHandlers.get(check(clientUsername))));
                
                System.out.println("After Decrption " + Decrypted);
            
                broadcastMessage(Decrypted);
                }
                catch (Exception e) {
       
                closeEverything(socket, bufferedReader, bufferedWriter);
                break;
            }
        }
    }


    public void broadcastMessage(String messageToSend) {
    	String encrypted="";
      System.out.println("before encryption:"+   messageToSend);
    	for (ClientHandler clientHandler : clientHandlers.keySet()) {
      
        	try {
      System.out.println(clientHandler.clientUsername);
      
                if (!clientHandler.clientUsername.equals(clientUsername)) {
                  try {
                    	encrypted=encrypt(messageToSend,Double.toString(clientHandlers.get(clientHandler)));
                      }
                  catch(Exception e) 
                  {
                	  
                	  e.printStackTrace();
                  
                  }
                    System.out.println("sending a message: "+encrypted);            
                    
                    
                	clientHandler.bufferedWriter.write(encrypted);
                    clientHandler.bufferedWriter.newLine();
                    clientHandler.bufferedWriter.flush();
                }
         } catch (IOException e) {
                // Gracefully close everything.
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
}


    public void removeClientHandler() {
        clientHandlers.remove(this);
        broadcastMessage("SERVER: " + clientUsername + " has left the chat!");
    }


    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
     
        removeClientHandler();
        try {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (bufferedWriter != null) {
                bufferedWriter.close();
            }
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
