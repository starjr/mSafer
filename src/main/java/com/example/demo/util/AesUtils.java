package com.example.demo.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * AES ��/��ȣȭ UTIL
 * 
 * @author Administrator
 * 
 */

public class AesUtils {
    
    protected final static Logger logger = LoggerFactory.getLogger(AesUtils.class);
    
    private static final int IV_LENGTH = 16;
    
    /**
     * AesUtil Constructor
     */
    public AesUtils() {
        super();
    }
    
    /**
     * HEX String; byte[]�� ��ȯ
     * 
     * @param hex
     * @return
     */
    public static byte[] hexToByteArray(String hex) {
        if (hex == null || hex.length() == 0) return null;
        byte[] ba = new byte[hex.length() / 2];
        for (int i = 0; i < ba.length; i++) {
            ba[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return ba;
    }
    
    /**
     * byte[]�� HEX String8�� ��ȯ
     * 
     * @param ba
     * @return
     */
    public static String byteArrayToHex(byte[] ba) {
        if (ba == null || ba.length == 0) return null;
        StringBuffer sb = new StringBuffer(ba.length * 2);
        String hexNumber;
        for (int x = 0; x < ba.length; x++) {
            hexNumber = "0" + Integer.toHexString(0xff & ba[x]);
            sb.append(hexNumber.substring(hexNumber.length() - 2));
        }
        return sb.toString();
    }
    
    /**
     * ��ȣȭ Ű ��
     * 
     * @param keyStr
     * @return
     */
    public static String makeKey(String keyStr) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 16; i++) {
            if (keyStr.length() > i) sb.append(keyStr.substring(i, i + 1));
            else sb.append(" ");
        }
        return sb.toString();
    }
    
    /**
     * ��ȣȭ ó��
     * 
     * @param pKey
     * @param message
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws CfoodException
     */
    public static String encrypt(String pKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String key = makeKey(pKey);
        
        byte[] encrypted = null;
        String encryptMsg = "";
        
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        encrypted = cipher.doFinal(message.getBytes());
        encryptMsg = Base64.encodeBase64String(encrypted);
        
        return encryptMsg;
    }
    
    /**
     * ��ȣȭ ó��
     * 
     * @param pKey
     * @param org
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws CfoodException
     */
    public static byte[] encryptByte(String pKey, byte[] org) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String key = makeKey(pKey);
        // System.out.println("org["+new String(org)+"]");
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        byte[] ret;
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        ret = cipher.doFinal(org);
        
        return Base64.encodeBase64(ret);
    }
    
    /**
     * ��ȣȭ ó��
     * 
     * @param pKey
     * @param org
     * @return
     * @throws CfoodException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decryptByte(String pKey, byte[] org) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String key = makeKey(pKey);
        
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher;
        byte[] ret;
        
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        ret = cipher.doFinal(Base64.decodeBase64(org));
        
        return ret;
    }
    
    /**
     * ��ȣȭ ó��
     * 
     * @param pKey
     * @param encrypted
     * @return
     * @throws CfoodException
     */
    public static String decrypt(String pKey, String encrypted) {
        String key = makeKey(pKey);
        String originalString = "";
        
        SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES");
            
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));
            originalString = new String(original, "EUC-KR");
            
        }
        catch (Exception e) {
            e.printStackTrace();
            //throw new CfoodException(ExceptionConstants.FAIL, e);
        }
        
        return originalString;
    }
    
    public static void encryptStream(InputStream in, OutputStream out, String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        
        SecureRandom r = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        r.nextBytes(iv);
        out.write(iv); // write IV as a prefix
        out.flush();
        // System.out.println(">>>>>>>>written"+Arrays.toString(iv));
        
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding"); // "DES/ECB/PKCS5Padding";"AES/CBC/PKCS5Padding"
        SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        out = new CipherOutputStream(out, cipher);
        byte[] buf = new byte[1024];
        int numRead = 0;
        while ((numRead = in.read(buf)) >= 0) {
            out.write(buf, 0, numRead);
        }
        out.close();
    }
    
    public static void decryptStream(InputStream in, OutputStream out, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, InvalidKeyException, InvalidAlgorithmParameterException {
        
        byte[] iv = new byte[IV_LENGTH];
        in.read(iv);
        // System.out.println(">>>>>>>>red"+Arrays.toString(iv));
        
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding"); // "DES/ECB/PKCS5Padding";"AES/CBC/PKCS5Padding"
        SecretKeySpec keySpec = new SecretKeySpec(password.getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        
        in = new CipherInputStream(in, cipher);
        byte[] buf = new byte[1024];
        int numRead = 0;
        while ((numRead = in.read(buf)) >= 0) {
            out.write(buf, 0, numRead);
        }
        out.close();
    }
    
    public static void executeFile(int mode, String inputFile, String outputFile, String password) {
        
        BufferedInputStream is = null;
        BufferedOutputStream os = null;
        
        try {
            is = new BufferedInputStream(new FileInputStream(inputFile));
            os = new BufferedOutputStream(new FileOutputStream(outputFile));
            
            if (mode == Cipher.ENCRYPT_MODE) {
                encryptStream(is, os, password);
            }
            else if (mode == Cipher.DECRYPT_MODE) {
                decryptStream(is, os, password);
            }
        }
        catch (Exception ioe) {
            //throw new CfoodException("", ioe);
        }
        finally {
            if (is != null) try {
                is.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
            if (os != null) try {
                os.close();
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        
    }
    
    public static void main(String[] args) throws Exception {
        String orgMsg = "test=mjshi";
        String encyString = AesUtils.encrypt("97eec80b64b9d208", "12345동해");// key, message
        System.out.println(encyString);
        System.out.println(AesUtils.decrypt("97eec80b64b9d208", encyString));
        // byte[] encyString = AesUtils.encryptByte("abcdef1234567890", "1234567890".getBytes());
        // System.out.println(new String(encyString));
        //
        // byte[] aaa = AesUtils.decryptByte("abcdef123456789f0", encyString);
        //
        // System.out.println("zzzz=>" + new String(aaa));
        
        // AesUtils.decryptByte(pKey, org)
        
        // encyString = StringUtils.remove(encyString, "=");
        // encyString = StringUtils.replaceEach(encyString, new String[] { "/" }, new String[] { "b" });
        // System.out.println("[encrypt]" + encyString);
        // System.out.println("[decrypt]" + AesUtils.decrypt("dkitec1234!", encyString));
        //
        // encyString = AesUtils.encrypt("dkitec1234!", "dkitec1234!");
        // System.out.println("[encrypt]" + encyString);
        // System.out.println("[decrypt]" + AesUtils.decrypt("dkitec1234!", encyString));
        //
        // encyString = AesUtils.encrypt("dkitec1234!", "smartav");
        // System.out.println("[encrypt]" + encyString);
        // System.out.println("[decrypt]" + AesUtils.decrypt("dkitec1234!", encyString));
        //
        // encyString = AesUtils.encrypt("dkitec1234!", "smartav2");
        // System.out.println("[encrypt]" + encyString);
        // System.out.println("[decrypt]" + AesUtils.decrypt("dkitec1234!", encyString));
    }
    
}
