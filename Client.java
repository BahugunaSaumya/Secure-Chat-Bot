//package main;
import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class Client {

    private static  Key secretKey = null;

    private Socket socket;
    
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private static byte[] key;
    private final int KEY_SIZE = 128;
    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;
    private String username;
int pub = 23;
int g = 9 ;
Double A,B,Adash;
String Astring,BString;
int privKey=0;
boolean check=false;
Random rn= new Random();
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
    public Client(Socket socket, String username) {
        try {
            this.socket = socket;
            this.username = username;
           
            try {
				privKey = rn.nextInt(8 - 4 + 1) + 4;
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            A = ((Math.pow(g, privKey)) % pub);
            Astring=Double.toString(A);
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.bufferedWriter= new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
          
        } catch (IOException e) {
            // Gracefully close everything.
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }
public void createkey() {
	try {
	BString=bufferedReader.readLine().split("/")[1];
	  bufferedWriter.write("/"+Astring);
      bufferedWriter.newLine();
      bufferedWriter.flush();
      
      B=Double.parseDouble(BString);
      Adash = ((Math.pow(B, privKey)) % pub);
      System.out.println("Symmetric Key:  "+Adash);
}catch(IOException e) {e.printStackTrace();}
}
    // Sending a message isn't blocking and can be done without spawning a thread, unlike waiting for a message.
    public void sendMessage() {
        try {
            // Initially send the username of the client.
            bufferedWriter.write(username);
            bufferedWriter.newLine();
            bufferedWriter.flush();
      
            // Create a scanner for user input.
            @SuppressWarnings("resource")
			Scanner scanner = new Scanner(System.in);
            // While there is still a connection with the server, continue to scan the terminal and then send the message.
            while (socket.isConnected()) {
                String messageToSend = scanner.nextLine();
                try{messageToSend=encrypt(username+": "+messageToSend,Double.toString(Adash));}catch(Exception e) {e.printStackTrace();}
                System.out.println("sent text:"  +messageToSend);
                bufferedWriter.write(messageToSend);
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (IOException e) {
            // Gracefully close everything.
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }


    public void listenForMessage() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msgFromGroupChat;
       while (socket.isConnected()) {
                    try {
                    	  if(check==false) {
                              createkey();
                              check=true;
                          }
                    	  else {   
                        msgFromGroupChat = bufferedReader.readLine();
                        System.out.println("encrypted: "+msgFromGroupChat);
                        try {
                        	msgFromGroupChat=decrypt(msgFromGroupChat,Double.toString(Adash));
                        }
                        catch(Exception e) {
                        	e.printStackTrace();
                        }
System.out.println("decrypted :"+msgFromGroupChat);
                    	  }} catch (IOException e) {
                  
                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }


    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
       
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


    public static void main(String[] args) throws IOException {

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your username for the group chat: ");
        String username = scanner.nextLine();

        Socket socket = new Socket("localhost", 1234);

      
        Client client = new Client(socket, username);
 
        client.listenForMessage();
        client.sendMessage();
    }
}

