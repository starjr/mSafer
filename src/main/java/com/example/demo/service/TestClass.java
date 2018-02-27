package com.example.demo.service;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class TestClass {

    public static byte[] iv = new SecureRandom().generateSeed(16);

    public static void main(String[] args) {
	
	//new TestClass().aaaa("");
	
	
    }
    
    public String aaaa(String bbb) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalStateException {
	
	System.out.println("base64-1:" + bbb);
	byte [] de = Base64.decodeBase64(bbb);
	KeyFactory serverKeyFactory = KeyFactory.getInstance("EC");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(de);
        PublicKey clientPubKey = serverKeyFactory.generatePublic(x509KeySpec);
        System.out.println("base64-2:" + Base64.encodeBase64String(de));
        System.out.println("Client public length: " + clientPubKey.getEncoded().length);
        System.out.println("Client public length: " + bytesToHex(clientPubKey.getEncoded()));
        System.out.println("Client public base64: " + Base64.encodeBase64String(clientPubKey.getEncoded()));
        
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
	KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
	keyPairGenerator.initialize(parameterSpec);
	KeyPair bobPair = keyPairGenerator.generateKeyPair();
	ECPublicKey bobPub = (ECPublicKey)bobPair.getPublic();
	ECPrivateKey bobPvt = (ECPrivateKey)bobPair.getPrivate();

	byte[] bobPubEncoded = bobPub.getEncoded();
	byte[] bobPvtEncoded = bobPvt.getEncoded();

	System.out.println("Server public length: " + bobPubEncoded.length);
	System.out.println("Server private length: " + bobPvtEncoded.length);
	
	System.out.println("Server public: " + bytesToHex(bobPubEncoded));
	System.out.println("Server private: " + bytesToHex(bobPvtEncoded));
	
	KeyAgreement bobKeyAgree = KeyAgreement.getInstance(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId(), "BC");
	bobKeyAgree.init(bobPvt);
	bobKeyAgree.doPhase(clientPubKey, true);
	
	System.out.println("len::"+bobKeyAgree.generateSecret(NISTObjectIdentifiers.id_aes128_CBC.getId()).getEncoded().length);
	System.out.println("Bob secret: " + bytesToHex(bobKeyAgree.generateSecret(NISTObjectIdentifiers.id_aes128_CBC.getId()).getEncoded()));
	
	//B65B4C8A1C797B867CE39F26DC97A0241A407FC79CF0D3CBA061A4A907CF3E1B
	//01B721695252A294AD568DC631B4E7FFE379DB5545FFCB8D887ECB070309D65DC0FF340E3E329D8299F25A5D62F7B2D175BBE8E0C309A5CA78610C22EC1CEB3A9D4E
	
	return bytesToHex(bobPub.getEncoded());
    }

    public static KeyPair generateECKeys() {
	try {
	    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");

	    keyPairGenerator.initialize(parameterSpec);

	    KeyPair keyPair = keyPairGenerator.generateKeyPair();
	    System.out.println("Private key length: " + keyPair.getPrivate().getEncoded().length);
	    System.out.println("Public key length: " + keyPair.getPublic().getEncoded().length);
	    return keyPair;
	} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
	    e.printStackTrace();
	    return null;
	}
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
	try {
	    KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
	    keyAgreement.init(privateKey);
	    keyAgreement.doPhase(publicKey, true);

	    SecretKey key = keyAgreement.generateSecret("AES");
	    System.out.println("Shared key length: " + key.getEncoded().length);
	    return key;
	} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	    return null;
	}
    }

    public static String encryptString(SecretKey key, String plainText) {
	try {
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
	    byte[] plainTextBytes = plainText.getBytes("UTF-8");
	    byte[] cipherText;

	    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	    cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
	    int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
	    encryptLength += cipher.doFinal(cipherText, encryptLength);

	    return bytesToHex(cipherText);
	} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
		| InvalidAlgorithmParameterException | UnsupportedEncodingException | ShortBufferException
		| IllegalBlockSizeException | BadPaddingException e) {
	    e.printStackTrace();
	    return null;
	}
    }

    public static String decryptString(SecretKey key, String cipherText) {
	try {
	    Key decryptionKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
	    IvParameterSpec ivSpec = new IvParameterSpec(iv);
	    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
	    byte[] cipherTextBytes = hexToBytes(cipherText);
	    byte[] plainText;

	    cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
	    plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
	    int decryptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);
	    decryptLength += cipher.doFinal(plainText, decryptLength);

	    return new String(plainText, "UTF-8");
	} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
		| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
		| ShortBufferException | UnsupportedEncodingException e) {
	    e.printStackTrace();
	    return null;
	}
    }

    public static String bytesToHex(byte[] data, int length) {
	String digits = "0123456789ABCDEF";
	StringBuffer buffer = new StringBuffer();

	for (int i = 0; i != length; i++) {
	    int v = data[i] & 0xff;

	    buffer.append(digits.charAt(v >> 4));
	    buffer.append(digits.charAt(v & 0xf));
	}

	return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
	return bytesToHex(data, data.length);
    }

    public static byte[] hexToBytes(String string) {
	int length = string.length();
	byte[] data = new byte[length / 2];
	for (int i = 0; i < length; i += 2) {
	    data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4)
		    + Character.digit(string.charAt(i + 1), 16));
	}
	return data;
    }

}
