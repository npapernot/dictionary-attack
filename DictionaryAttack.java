//Author: Nicolas Papernot

import java.security.*;
import java.io.*;
import java.util.*;
import java.lang.StringBuilder;
import javax.xml.bind.DatatypeConverter;

public class DictionaryAttack {
	//Extracted from http://www.jmdoudoux.fr/java/dej/chap-jca.htm
	public static String bytesToHex(byte[] b) {
	      char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7',
	                         '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	      StringBuffer buf = new StringBuffer();
	      for (int j=0; j<b.length; j++) {
	         buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
	         buf.append(hexDigit[b[j] & 0x0f]);
	      }
	      return buf.toString();
	   }
	
	//This method takes a string, computes its SHA-1 hash, 
	//and converts it into HEX using the bytesToHex method
	public static String stringToSha1(String input) throws Exception {
		//Setup a MessageDigest for SHA1 
		MessageDigest md = MessageDigest.getInstance("SHA1");
		md.reset();
		
		//Setup the MessageDigest with our input string
        md.update(input.getBytes("UTF-8"));
        
        //Convert the string's digest to HEX
        String sha1 = bytesToHex(md.digest());
		return sha1;
	}
	
	//This method takes a byte array holding a salt and a string input
	//and returns the concatenated salt || input in byte array format
	public static byte[] concatenate_salt_with_string(byte[] salt, String input) throws Exception {
		//Convert input string to bytes
		byte[] input_byte = input.getBytes("UTF-8");
		//Create byte array sufficiently large
		byte[] concatenated = new byte[salt.length + input_byte.length];
		//Insert the salt first
		System.arraycopy(salt, 0, concatenated, 0, salt.length);
		//Insert the input string converted to bytes
		System.arraycopy(input_byte, 0, concatenated, salt.length, input_byte.length);
		//Return the concatenated salt and string in a byte array
		return concatenated;
	}

	//This method takes a string, a salt, computes its salted SHA-1 hash, 
	//and converts it into HEX using the bytesToHex method
	public static String stringToSha1_salted(byte[] salt, String input) throws Exception {
		//Setup a MessageDigest for SHA1 
		MessageDigest md = MessageDigest.getInstance("SHA1");
		md.reset();
		
		//Use the concatenate_salt_with_string method to concatenate the salt with the input
		byte[] concatenated = concatenate_salt_with_string(salt, input);
		
		//Setup the MessageDigest with our input string
        md.update(concatenated);
        
        //Convert the string's digest to HEX
        String sha1 = bytesToHex(md.digest());
		return sha1;
	}
	
	public static void main(String[] args) throws Exception {
		//Notify the user the program is starting.
		System.out.println("Let's get things started.");
		
		//Load the provided password file into stream and buffer
        File passwords_file = new File("/Users/nicolas/Documents/eclipseworkspace/dictionaryattack/src/password.txt");
    	FileInputStream password_stream = new FileInputStream(passwords_file);
    	BufferedReader password_buffer = new BufferedReader(new InputStreamReader(password_stream));
     
    	//Initialize 3 hashmaps, one for non-salted passwords, one for salted passwords,
    	//and one for the salts of salted passwords. 
    	Map<String, String> non_salted_passwords = new HashMap<String, String>();
    	Map<String, String> salted_passwords = new HashMap<String, String>();
    	Map<String, String> salted_passwords_salts = new HashMap<String, String>();
    	
    	//We parse the buffer to extract user account names and passwords
    	String password_file_line = null;
    	while ((password_file_line = password_buffer.readLine()) != null) {
    		String[] splited = password_file_line.split("\\s+");
    		
    		//First case: password hashed with no salt
    		if(splited.length == 3){
    			non_salted_passwords.put(splited[0], splited[2]);
    		}
    		
    		//Second case: password hashed with a salt
    		else{
    			salted_passwords.put(splited[0], splited[3]);
    			salted_passwords_salts.put(splited[0], splited[2]);
    		}
    	}
    	
    	//We are done reading the password file, we can close its buffer
    	password_buffer.close();
		
		//Load the provided Dictionary into stream and buffer
        File fin = new File("/Users/nicolas/Documents/eclipseworkspace/dictionaryattack/src/english.0");
    	FileInputStream fis = new FileInputStream(fin);
    	 
    	//Construct BufferedReader from InputStreamReader
    	BufferedReader br = new BufferedReader(new InputStreamReader(fis));
     
    	//We parse the buffer to test matches for hashed password,
    	//reversed passwords, non vowel passwords, and salted versions of password (if required). 
    	String line = null;
    	while ((line = br.readLine()) != null) {
    		//We first iterate through the non salted passwords
    		Iterator non_salted_passwords_it = non_salted_passwords.entrySet().iterator();
    		while (non_salted_passwords_it.hasNext()) {
    			//We extract the key,value pair from the HashTable entry
    			Map.Entry pair = (Map.Entry)non_salted_passwords_it.next();
    	        String account_name = pair.getKey().toString(); 
    	        String account_password_hash = pair.getValue().toString();

    	        //We test if the password matches an unmodified dictionary entry
    	        if(account_password_hash.equals(stringToSha1(line))){
    	        	System.out.println(account_name + "'s password is '" + line + "'");
        		}
    	        
    	        //We test if the password matches a reversed dictionary entry
    	        String reversed_line = new StringBuilder(line).reverse().toString();
    	        if(account_password_hash.equals(stringToSha1(reversed_line))){
    	        	System.out.println(account_name + "'s password is '" + reversed_line + "'");
        		}
    	        
    	        //We test if the password matches a dictionary entry without its vowels
    	        String line_without_vowels = line.replaceAll("[AEIOUaeiou]", "");
    	        if(account_password_hash.equals(stringToSha1(line_without_vowels))){
    	        	System.out.println(account_name + "'s password is '" + line_without_vowels + "'");
        		}
    		}
    		
    		//We then iterate through the salted passwords
    		Iterator salted_passwords_it = salted_passwords.entrySet().iterator();
    		while (salted_passwords_it.hasNext()) {
    			//We extract the key,value pair from the HashTable entry
    			Map.Entry salted_pair = (Map.Entry)salted_passwords_it.next();
    	        String account_name = salted_pair.getKey().toString(); 
    	        String account_password_hash = salted_pair.getValue().toString();
    	        //We extract the corresponding salt from the HashTable of salts
    	        byte[] account_password_hash_salt = DatatypeConverter.parseHexBinary(salted_passwords_salts.get(account_name));
      	        
    	        //We test if the password matches an unmodified dictionary entry
    	        if(account_password_hash.equals(stringToSha1_salted(account_password_hash_salt,line))){
    	        	System.out.println(account_name + "'s password is '" + line + "'");
        		}
    	        
    	        //We test if the password matches a reversed dictionary entry
    	        String reversed_line = new StringBuilder(line).reverse().toString();
    	        if(account_password_hash.equals(stringToSha1_salted(account_password_hash_salt,reversed_line))){
    	        	System.out.println(account_name + "'s password is '" + reversed_line + "'");
        		}
    	        
    	        //We test if the password matches a dictionary entry without its vowels
    	        String line_without_vowels = line.replaceAll("[AEIOUaeiou]", "");
    	        if(account_password_hash.equals(stringToSha1_salted(account_password_hash_salt,line_without_vowels))){
    	        	System.out.println(account_name + "'s password is '" + line_without_vowels + "'");
        		}
    		}
    	}
     
    	//We are done using the dictionary file, we can close its buffer
    	br.close();
    	
    	//Notify the user our program is done running.
    	System.out.println("The program terminated.");
	}
}
