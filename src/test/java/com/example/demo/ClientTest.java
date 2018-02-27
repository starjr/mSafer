package com.example.demo;

import java.io.IOException;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

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
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class ClientTest {

    public static byte[] iv = new SecureRandom().generateSeed(16);

    public static void main(String[] args) throws ClientProtocolException, IOException, InvalidKeyException, IllegalStateException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {

	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	long start = System.currentTimeMillis();

	String plainText = "Look mah, I'm a message!";
	System.out.println("Original plaintext message: " + plainText);

	// Initialize two key pairs
	System.out.println("==y>" + (System.currentTimeMillis() - start));
	KeyPair keyPairA = generateECKeys();
	System.out.println("==1>" + (System.currentTimeMillis() - start));
	// Create two AES secret keys to encrypt/decrypt the message
	
	//byte[] bb = keyPairA.getPublic().getEncoded();
	byte[] bb = Base64.decodeBase64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcIldZ5ETc1sxerq+sGCxzaC6hluiBYf+sn29cb76HEAUPSN8UKPf7MtlsFQxP8bkov150qdxPKbYrbkYTTnT8LBgni8zhGbgcNAPl5AyOuLkS7tOcDiYfbZbd5gAY4lc"); 
	
	System.out.println(bytesToHex(bb));
	
	CloseableHttpClient httpclient = HttpClients.createDefault();
        try {
            HttpPost httpPost = new HttpPost("http://localhost:8080/aaaa");
            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair("c", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhXolMfJZxszEHZJ7oPYpiTayU5HFrVB/esO4/0M0Mytli1UgS/USbHC+L3ctHp8pjf/wz25yIgYRIiaWpVB+6g=="));
            httpPost.setEntity(new UrlEncodedFormEntity(params));

            // Create a custom response handler
            ResponseHandler<String> responseHandler = new ResponseHandler<String>() {

                @Override
                public String handleResponse(
                        final HttpResponse response) throws ClientProtocolException, IOException {
                    int status = response.getStatusLine().getStatusCode();
                    if (status >= 200 && status < 300) {
                        HttpEntity entity = response.getEntity();
                        return entity != null ? EntityUtils.toString(entity) : null;
                    } else {
                        throw new ClientProtocolException("Unexpected response status: " + status);
                    }
                }

            };
            String responseBody = httpclient.execute(httpPost, responseHandler);
            responseBody = StringUtils.trim(responseBody);
            System.out.println("----------------------------------------");
            System.out.println(responseBody);
            System.out.println("----------------------------------------");
            
            X509EncodedKeySpec sk = new X509EncodedKeySpec(hexToBytes(responseBody));
            KeyFactory aliceKf = KeyFactory.getInstance("EC");
            PublicKey remoteBobPub = aliceKf.generatePublic(sk);
            

            KeyAgreement aliceKeyAgree = KeyAgreement.getInstance(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId(), "BC");
            aliceKeyAgree.init(keyPairA.getPrivate());
            aliceKeyAgree.doPhase(remoteBobPub, true);
            System.out.println(aliceKeyAgree.getAlgorithm());
            System.out.println("Alice secret: " + bytesToHex(aliceKeyAgree.generateSecret(NISTObjectIdentifiers.id_aes128_CBC.getId()).getEncoded()));
        } finally {
            httpclient.close();
        }
	
//	SecretKey secretKeyA = generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
//	
//	SecretKey secretKeyB = generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());
//	System.out.println(bytesToHex(secretKeyB.getEncoded()));
//
//	start = System.currentTimeMillis();
//	System.out.println("==2>" + (System.currentTimeMillis() - start));
//
//	// Encrypt the message using 'secretKeyA'
//	String cipherText = encryptString(secretKeyA, plainText);
//	System.out.println("Encrypted cipher text: " + cipherText);
//
//	System.out.println("==3>" + (System.currentTimeMillis() - start));
//	// Decrypt the message using 'secretKeyB'
//	String decryptedPlainText = decryptString(secretKeyB, cipherText);
//	System.out.println("Decrypted cipher text: " + decryptedPlainText);
//
//	System.out.println("==4>" + (System.currentTimeMillis() - start));

    }

    public static KeyPair generateECKeys() {
	try {
	    ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");

	    keyPairGenerator.initialize(parameterSpec, new SecureRandom());

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
