package com.example.demo.util;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class SecurityHashUtils {
    
    public static String md5Encrypt(String src) {
        String out = "";
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(src.getBytes());
            byte byteData[] = md.digest();
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }
            out = sb.toString();
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            out = null;
        }
        return out;
    }
    
    public static String sha256Encrypt(String src) {
        MessageDigest md;
        String out = "";
        try {
            md = MessageDigest.getInstance("SHA-256");
            
            md.update(src.getBytes());
            byte[] mb = md.digest();
            
            for (int i = 0; i < mb.length; i++) {
                byte temp = mb[i];
                String s = Integer.toHexString(new Byte(temp));
                while (s.length() < 2) {
                    s = "0" + s;
                }
                s = s.substring(s.length() - 2);
                out += s;
            }
            // System.out.println(out.length());
            // System.out.println("CRYPTO: " + out);
            
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
        
        return out;
    }
    
    public static String sha256Encrypt(byte[] src) {
        MessageDigest md;
        String out = "";
        try {
            md = MessageDigest.getInstance("SHA-256");
            
            md.update(src);
            byte[] mb = md.digest();
            
            for (int i = 0; i < mb.length; i++) {
                byte temp = mb[i];
                String s = Integer.toHexString(new Byte(temp));
                while (s.length() < 2) {
                    s = "0" + s;
                }
                s = s.substring(s.length() - 2);
                out += s;
            }
            // System.out.println(out.length());
            // System.out.println("CRYPTO: " + out);
            
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("ERROR: " + e.getMessage());
        }
        
        return out;
    }
    
    public static String hmac(String timestamp, String message, String base64EncodedKey) {
    	String hmac = null;
    	
		try {
			Mac sha256_HMAC;
			
			sha256_HMAC = Mac.getInstance("HmacSHA256");
			SecretKeySpec secret_key = new SecretKeySpec(Base64.decodeBase64(base64EncodedKey), "HmacSHA256");
			sha256_HMAC.init(secret_key);
			hmac = Base64.encodeBase64String(sha256_HMAC.doFinal((timestamp+message+base64EncodedKey).getBytes()));
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return hmac;
    }
    
    public static void main(String[] args) throws Exception {
        String test0001 = "kogas123?";
        
        System.out.println(SecurityHashUtils.md5Encrypt(test0001));
    }
}
