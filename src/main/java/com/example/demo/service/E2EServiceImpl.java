package com.example.demo.service;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.tomcat.util.buf.HexUtils;
import org.springframework.stereotype.Service;

import com.example.demo.util.AesUtils;
import com.example.demo.util.SecurityHashUtils;





/**
 * Diffie-Hellman 키 동의 프로토콜
 * 
 * @author Administrator
 * 
 */
@Service
public class E2EServiceImpl implements E2EService {
    
    // // The 1024 bit Diffie-Hellman modulus values used by SKIP
    private static final byte skip1024ModulusBytes[] = { (byte) 0xF4, (byte) 0x88, (byte) 0xFD, (byte) 0x58, (byte) 0x4E, (byte) 0x49, (byte) 0xDB, (byte) 0xCD, (byte) 0x20, (byte) 0xB4, (byte) 0x9D, (byte) 0xE4, (byte) 0x91, (byte) 0x07, (byte) 0x36, (byte) 0x6B, (byte) 0x33, (byte) 0x6C, (byte) 0x38, (byte) 0x0D, (byte) 0x45, (byte) 0x1D, (byte) 0x0F, (byte) 0x7C, (byte) 0x88, (byte) 0xB3, (byte) 0x1C, (byte) 0x7C, (byte) 0x5B, (byte) 0x2D, (byte) 0x8E, (byte) 0xF6, (byte) 0xF3, (byte) 0xC9, (byte) 0x23, (byte) 0xC0, (byte) 0x43, (byte) 0xF0, (byte) 0xA5, (byte) 0x5B, (byte) 0x18, (byte) 0x8D, (byte) 0x8E, (byte) 0xBB, (byte) 0x55, (byte) 0x8C, (byte) 0xB8, (byte) 0x5D, (byte) 0x38, (byte) 0xD3, (byte) 0x34, (byte) 0xFD, (byte) 0x7C, (byte) 0x17, (byte) 0x57, (byte) 0x43, (byte) 0xA3, (byte) 0x1D, (byte) 0x18, (byte) 0x6C, (byte) 0xDE, (byte) 0x33, (byte) 0x21, (byte) 0x2C, (byte) 0xB5, (byte) 0x2A, (byte) 0xFF, (byte) 0x3C, (byte) 0xE1, (byte) 0xB1, (byte) 0x29, (byte) 0x40, (byte) 0x18, (byte) 0x11, (byte) 0x8D, (byte) 0x7C, (byte) 0x84, (byte) 0xA7, (byte) 0x0A, (byte) 0x72, (byte) 0xD6, (byte) 0x86, (byte) 0xC4, (byte) 0x03, (byte) 0x19, (byte) 0xC8, (byte) 0x07, (byte) 0x29, (byte) 0x7A, (byte) 0xCA, (byte) 0x95, (byte) 0x0C, (byte) 0xD9, (byte) 0x96, (byte) 0x9F, (byte) 0xAB, (byte) 0xD0, (byte) 0x0A, (byte) 0x50, (byte) 0x9B, (byte) 0x02, (byte) 0x46, (byte) 0xD3, (byte) 0x08, (byte) 0x3D, (byte) 0x66, (byte) 0xA4, (byte) 0x5D, (byte) 0x41, (byte) 0x9F, (byte) 0x9C, (byte) 0x7C, (byte) 0xBD, (byte) 0x89, (byte) 0x4B, (byte) 0x22, (byte) 0x19, (byte) 0x26, (byte) 0xBA, (byte) 0xAB, (byte) 0xA2, (byte) 0x5E, (byte) 0xC3, (byte) 0x55, (byte) 0xE9, (byte) 0x2F, (byte) 0x78, (byte) 0xC7 };
    
    // // The SKIP 1024 bit modulus
    private static final BigInteger skip1024Modulus = new BigInteger(1, skip1024ModulusBytes);
    //
    // // The base used with the SKIP 1024 bit modulus
    private static final BigInteger skip1024Base = BigInteger.valueOf(2);
    
    @PostConstruct
    public void init() {
	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    public static void main(String args[]) throws InvalidKeySpecException {
        System.out.println(skip1024ModulusBytes.length);
        String ae = "!@";
        System.out.println(Base64.encodeBase64String(ae.getBytes()));
        String ab = "3BFE3F792EAC77C487883AA9CD61523855E1D919B77FD01C19A9AF6E32CC12C5740D7306F20567963A1760DDDA097FCA3A3F0CE0910DC1C902A2947BE45840353EF3C870B503E16B01CC910EDD9605B0F4398877650DFA4A767674F361AA79643E56AEFB90B883DE8A223FC2F87327F7B476A58F629D531013344BE69DC06771";
        String xx = "3082011F30819506092A864886F70D01030130818702818100F488FD584E49DBCD20B49DE49107366B336C380D451D0F7C88B31C7C5B2D8EF6F3C923C043F0A55B188D8EBB558CB85D38D334FD7C175743A31D186CDE33212CB52AFF3CE1B1294018118D7C84A70A72D686C40319C807297ACA950CD9969FABD00A509B0246D3083D66A45D419F9C7CBD894B221926BAABA25EC355E92F78C7020102038184000281803BFE3F792EAC77C487883AA9CD61523855E1D919B77FD01C19A9AF6E32CC12C5740D7306F20567963A1760DDDA097FCA3A3F0CE0910DC1C902A2947BE45840353EF3C870B503E16B01CC910EDD9605B0F4398877650DFA4A767674F361AA79643E56AEFB90B883DE8A223FC2F87327F7B476A58F629D531013344BE69DC06771";
        byte[] ac = HexUtils.fromHexString(ab);
        
//        try {
//            System.out.println(">>leng" + ac.length + "[" + bytesToBigInteger(ac).intValue() + "]");
//            PublicKey pk = getPublicKey(new BigInteger(1, ac), skip1024Modulus, skip1024Base);
//            
//            // Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//            // DHParameterSpec dhParams = new DHParameterSpec(skip1024Modulus, skip1024Base);
//            // org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey pk = (org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey) getPublicKey(bytesToBigInteger(ac), skip1024Modulus, skip1024Base);
//            // System.out.println("[" + pk.getFormat() + "]");
//            // String a1 = HexUtils.toHexString(pk.getEncoded());
//            // System.out.println("[" + a1.length() + "]");
//            // System.out.println(a1);
//            // System.out.println(xx);
//            // System.out.println(ab);
//            //
//            // DHPublicKeySpec keySpec = new DHPublicKeySpec(pk.getY(), skip1024Modulus, skip1024Base);
//            //
//            // KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
//            // PublicKey publicKey = keyFactory.generatePublic(keySpec);
//            //
//            // System.out.println(HexUtils.toHexString(publicKey.getEncoded()));
//            //
//            // X509EncodedKeySpec ghhh = new X509EncodedKeySpec(ac);
//            // PublicKey publicKeyx = KeyFactory.getInstance("DH", "BC").generatePublic(ghhh);
//            //
//            // DHParameterSpec dhParamSpec = ((org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey) publicKey).getParams();
//            // System.out.println("g:" + dhParamSpec.getG());
//            // System.out.println("p:" + dhParamSpec.getP());
//            // System.out.println("l:" + dhParamSpec.getL());
//            //
//            // KeyPairGenerator serverKeyPairGen = KeyPairGenerator.getInstance("DH");
//            // serverKeyPairGen.initialize(dhParams);
//            // KeyPair serverKeyPair = serverKeyPairGen.generateKeyPair();
//            // serverKeyPair.getPrivate();
//            //
//            // KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");
//            //
//            // agreement.init(serverKeyPair.getPrivate());
//            // agreement.doPhase(publicKey, true);
//            //
//            // byte[] secret = agreement.generateSecret();
//            //
//            // String sc = HexUtils.toHexString(secret);
//            // System.out.println("[" + secret.length + "]" + sc);
//            
//            // pk.get
//            
//            // generate secret key for B, hash it.
//            //
//            //
//            // KeyFactory serverKeyFactory = KeyFactory.getInstance("DH");
//            // X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(ac);
//            // PublicKey clientPubKey = serverKeyFactory.generatePublic(x509KeySpec);
//            //
//            // KeyFactory keyFactory = KeyFactory.getInstance("DH");
//            //
//            // DHParameterSpec dhParamSpec = new DHParameterSpec(skip1024Modulus, skip1024Base, 512);
//            // System.out.println("dhParamSpec :" + dhParamSpec.getL());
//            //
//            // KeyPairGenerator serverKeyPairGen = KeyPairGenerator.getInstance("DH");
//            // serverKeyPairGen.initialize(dhParamSpec);
//            // KeyPair serverKeyPair = serverKeyPairGen.generateKeyPair();
//            //
//            // KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
//            // serverKeyAgree.init(serverKeyPair.getPrivate());
//            //
//            // KeySpec dhspec = new DHPublicKeySpec(new BigInteger(1, ac), skip1024Modulus, skip1024Base);
//            // PublicKey pk = keyFactory.generatePublic(dhspec);
//            //
//            // System.out.println(pk);
//            //
//            // System.out.println(pk.getFormat());
//            //
//            // serverKeyAgree.doPhase(clientPubKey, true);
//        }
//        catch (NoSuchAlgorithmException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        
//         catch (NoSuchProviderException e) {
//         // TODO Auto-generated catch block
//         e.printStackTrace();
//         }
//         catch (InvalidAlgorithmParameterException e) {
//         // TODO Auto-generated catch block
//         e.printStackTrace();
//         }
//         catch (InvalidKeyException e) {
//         // TODO Auto-generated catch block
//         e.printStackTrace();
//         }
//        catch (NoSuchProviderException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
        
         try {
         PublicKey pk = getPublicKey(bytesToBigInteger(HexUtils.fromHexString(ab)), skip1024Modulus, skip1024Base);
         System.out.println(Base64.encodeBase64String(pk.getEncoded()));
         }
         catch (Exception e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
         }
         System.out.println(ab.length());
         byte[] bClientPublicKey = Base64.decodeBase64(ab); // HexUtils.fromHexString(ab); // Base64.decodeBase64(ab);
         String ga = HexUtils.toHexString(bClientPublicKey);
         System.out.println(ga);
         System.out.println(bClientPublicKey.length);
        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */
        
//        /**
//         * 클라이언트가 전송한 공개키로 DH 공개키를 생성
//         */
//         KeyFactory serverKeyFactory;
//         try {
//         // serverKeyFactory = KeyFactory.getInstance("DH");
//         // X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bClientPublicKey);
//         // PublicKey clientPubKey = serverKeyFactory.generatePublic(x509KeySpec);
//        
//         }
//         catch (NoSuchAlgorithmException e) {
//         // TODO Auto-generated catch block
//         e.printStackTrace();
//         }
//         catch (InvalidKeySpecException e) {
//         // TODO Auto-generated catch block
//         e.printStackTrace();
//         }
        
    }
    
    @Override
    public String getServerPublicKey(String id, String clientPublicKey) {
        
        String serverPublicKey = null;
        
        TestClass tc = new TestClass();
        
        try {
	    try {
		try {
		    serverPublicKey = tc.aaaa(clientPublicKey);
		} catch (InvalidKeyException | IllegalStateException e) {
		    // TODO Auto-generated catch block
		    e.printStackTrace();
		}
	    } catch (NoSuchProviderException | InvalidAlgorithmParameterException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	    }
	} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}
//        
//        try {
//            
//            byte[] bClientPublicKey = Base64.decodeBase64(clientPublicKey);
//            
//            String x = HexUtils.toHexString(bClientPublicKey);
//            System.out.println("=========== clientPublicKey ============== ss [" + x.length() + "]");
//            System.out.println(x);
//            System.out.println("=========== clientPublicKey ============== ee");
//            /*
//             * Let's turn over to Bob. Bob has received Alice's public key
//             * in encoded format.
//             * He instantiates a DH public key from the encoded key material.
//             */
//            
//            /**
//             * 클라이언트가 전송한 공개키로 DH 공개키를 생성
//             */
//            KeyFactory serverKeyFactory = KeyFactory.getInstance("DH");
//            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bClientPublicKey);
//            PublicKey clientPubKey = serverKeyFactory.generatePublic(x509KeySpec);
//            
//            System.out.println("clientPublic Key Spec================>sss");
//            System.out.println(clientPubKey);
//            System.out.println("clientPublic Key Spec================>eee");
//            
//            /**
//             * 클라이언트의 공개키로 부터 DH Parameter를 추출
//             */
//            DHParameterSpec dhParamSpec = ((DHPublicKey) clientPubKey).getParams();
//            System.out.println("g:" + dhParamSpec.getG());
//            System.out.println("p:" + dhParamSpec.getP());
//            System.out.println("l:" + dhParamSpec.getL());
//            /**
//             * 서버의 개인키, 공개키를 생성
//             */
//            // System.out.println("BOB: Generate DH keypair ...");
//            KeyPairGenerator serverKeyPairGen = KeyPairGenerator.getInstance("DH");
//            serverKeyPairGen.initialize(dhParamSpec);
//            KeyPair serverKeyPair = serverKeyPairGen.generateKeyPair();
//            
//            /**
//             * 서버의 키 동의 객체를 생성 및 초기화
//             */
//            // System.out.println("BOB: Initialization ...");
//            KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
//            serverKeyAgree.init(serverKeyPair.getPrivate());
//            
//            /**
//             * 클라이언트에서 전송할 서버 공개키를 추출
//             */
//            byte[] serverPubKeyEnc = serverKeyPair.getPublic().getEncoded();
//            
//            String y = HexUtils.toHexString(serverPubKeyEnc);
//            System.out.println("=========== serverPublicKey ============== ss [" + y.length() + "]");
//            System.out.println(y);
//            System.out.println("=========== serverPublicKey ============== ee");
//            
//            serverPublicKey = Base64.encodeBase64String(serverPubKeyEnc);
//            
//            /**
//             * 키에 대한 동의 실행
//             */
//            serverKeyAgree.doPhase(clientPubKey, true);
//            
//            /**
//             * AES 알고리즘에 대한 암호화 키 생성
//             */
//            SecretKey secretKey = serverKeyAgree.generateSecret("AES");
//            
//            System.out.println("len::" + secretKey.getEncoded().length); 
//            String encAesSecreyKey = Base64.encodeBase64String(secretKey.getEncoded());
//            System.out.println("encAesSecreyKey::" + encAesSecreyKey);
//            
//            
//            /**
//             * Hazelcast에 해당 클라이언트에 대한 암/복호화 정보를 저장
//             */
//            
//            // set은 old값을 리턴하지 않고, put은 old값을 리턴한다. old값이 필요없다면 set이 성능상으로나 뭐로나 좋다.
//            // key는 설정값에 의해 30분간만 유효
//            ///e2eKeyRepository.set(id, encAesSecreyKey, 30, TimeUnit.MINUTES);
//            
//            //logger.debug("exChangeKey id[{}]key[{}]", id, encAesSecreyKey);
//            
//        }
//        catch (InvalidKeyException e) {
//        }
//        catch (IllegalStateException e) {
//        }
//        catch (NoSuchAlgorithmException e) {
//        }
//        catch (InvalidAlgorithmParameterException e) {
//        }
//        catch (InvalidKeySpecException e) {
//        }
        
        return serverPublicKey;
    }
    
    @Override
    public String getKey(String id) {
        //return e2eKeyRepository.get(id);
	
	return null;
    }
    
    @Override
    public byte[] encrypt(String id, byte[] sourceMessage) {
        String encKey = getKey(id);
        byte[] resultMessage = null;
        
        if (StringUtils.isEmpty(encKey)) {
            //throw new ServerException(ErrorConstant.E2E_KEY_NOT_EXIST, sourceMessage);
        }
        
        try {
            //logger.debug("encKey [{}]", encKey);
            resultMessage = AesUtils.encryptByte(encKey, sourceMessage);
        }
        catch (Exception ex) {
            //logger.error(ExceptionUtils.getStackTrace(ex));
            //throw new ServerException(ErrorConstant.E2E_ENCODE_ERROR, ex, sourceMessage);
        }
        return resultMessage;
    }
    
    @Override
    public byte[] decrypt(String id, byte[] sourceMessage) {
        String decKey = getKey(id);
        byte[] resultMessage = null;
        
        if (StringUtils.isEmpty(decKey)) {
            //throw new ServerException(ErrorConstant.E2E_KEY_NOT_EXIST);
        }
        
        try {
            //logger.debug("decKey [{}]", decKey);
            resultMessage = AesUtils.decryptByte(decKey, sourceMessage);
        }
        catch (Exception ex) {
            //logger.error(ExceptionUtils.getStackTrace(ex));
            //throw new ServerException(ErrorConstant.E2E_DECODE_ERROR, ex, sourceMessage);
        }
        return resultMessage;
    }
    
    public static PublicKey getPublicKey(BigInteger publicKey, BigInteger p, BigInteger g) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        DHPublicKeySpec dhspec = new DHPublicKeySpec(publicKey, p, g);
        
        KeyFactory keyFact = KeyFactory.getInstance("DH");
        PublicKey pubKey = keyFact.generatePublic(dhspec);
        
        return pubKey;
    }
    
    public static BigInteger bytesToBigInteger(byte[] bytes) {
        /* Pad with 0x00 so we don't get a negative BigInteger!!! */
        ByteBuffer key = ByteBuffer.allocate(bytes.length + 1);
        
        key.put((byte) 0x00);
        key.put(bytes);
        
        return new BigInteger(key.array());
    }
    
    @Override
    public String getServerPublicKeyHex(String id, String clientPublicKey) {
        
        String serverPublicKey = null;
        
        try {
            
            System.out.println("=========== clientPublicKey ============== ss [" + clientPublicKey.length() + "]");
            System.out.println(clientPublicKey);
            System.out.println("=========== clientPublicKey ============== ee");
            
            BigInteger bi = bytesToBigInteger(HexUtils.fromHexString(clientPublicKey));
            
            System.out.println("intValue==>" + bi.intValue());
            
            DHPublicKey clientPubKey = (DHPublicKey) getPublicKey(bi, skip1024Modulus, skip1024Base);
            
            System.out.println("clientPubKey.getAlgorithm()::" + clientPubKey.getAlgorithm());
            System.out.println("clientPubKey.getFormat()::" + clientPubKey.getFormat());
            
            System.out.println(clientPubKey);
            
            /**
             * 클라이언트의 공개키로 부터 DH Parameter를 추출
             */
            DHParameterSpec dhParamSpec = clientPubKey.getParams();
            
            byte[] bb = clientPubKey.getEncoded();
            System.out.println("=========== clientPublicKey2222222 ============== ss");
            System.out.println(HexUtils.toHexString(bb));
            System.out.println("=========== clientPublicKey2222222 ============== ee");
            
            System.out.println("g:" + dhParamSpec.getG());
            System.out.println("p:" + dhParamSpec.getP());
            System.out.println("l:" + dhParamSpec.getL());
            // DHParameterSpec dhParamSpec = new DHParameterSpec(skip1024Modulus, skip1024Base);
            
            System.out.println("========dhParamSpec======>ss");
            System.out.println(dhParamSpec);
            System.out.println("========dhParamSpec======>ee");
            
            /**
             * 서버의 개인키, 공개키를 생성
             */
            // System.out.println("BOB: Generate DH keypair ...");
            KeyPairGenerator serverKeyPairGen = KeyPairGenerator.getInstance("DH");
            serverKeyPairGen.initialize(dhParamSpec);
            KeyPair serverKeyPair = serverKeyPairGen.generateKeyPair();
            
            /**
             * 서버의 키 동의 객체를 생성 및 초기화
             */
            // System.out.println("BOB: Initialization ...");
            KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DH");
            serverKeyAgree.init(serverKeyPair.getPrivate());
            
            /**
             * 클라이언트에서 전송할 서버 공개키를 추출
             */
            byte[] serverPubKeyEnc = serverKeyPair.getPublic().getEncoded();
            
            DHPublicKey dhk = (DHPublicKey) serverKeyPair.getPublic();
            byte[] dhkbt = dhk.getY().toByteArray();
            serverPublicKey = HexUtils.toHexString(dhkbt);
            
            System.out.println("=========== serverPublicKey ============== ss [" + dhk.getY().bitLength() + "][" + dhkbt.length + "][" + serverPublicKey.length() + "]");
            System.out.println(serverPublicKey);
            System.out.println("=========== serverPublicKey ============== ee");
            
            /**
             * 키에 대한 동의 실행
             */
            serverKeyAgree.doPhase(clientPubKey, true);
            
            byte[] bKey = serverKeyAgree.generateSecret();
            
            String hexKey = HexUtils.toHexString(bKey);
            
            System.out.println(">>>>>>>>>>>>>>>>>>>>>> hex key >>>> ss [" + hexKey.length() + "]");
            System.out.println(hexKey);
            System.out.println(">>>>>>>>>>>>>>>>>>>>>> hex key >>>> ee");
            
            String sha256Key = SecurityHashUtils.sha256Encrypt(bKey); // 64byte
            System.out.println(">>>>>>>>>>>>>>>>>>>>>> sha256 key >>>> ss [" + sha256Key.length() + "]");
            System.out.println(sha256Key);
            System.out.println(">>>>>>>>>>>>>>>>>>>>>> sha256 key >>>> ee");
            
            /**
             * AES 알고리즘에 대한 암호화 키 생성
             * oracle jdk에서는 기본적으로 16byte의 aes암호화 키만 가능하므로, 16자리만 자름.
             */
            String encAesSecretKey = StringUtils.left(sha256Key, 16);
            
            /**
             * Hazelcast에 해당 클라이언트에 대한 암/복호화 정보를 저장
             */
            
            // set은 old값을 리턴하지 않고, put은 old값을 리턴한다. old값이 필요없다면 set이 성능상으로나 뭐로나 좋다.
            // key는 설정값에 의해 30분간만 유효
            //e2eKeyRepository.set(id, encAesSecretKey, 30, TimeUnit.MINUTES);
            
            System.out.println(">>>>>>>>>>>>>>>>>>>>>> final save key >>>> ss [" + encAesSecretKey.length() + "]");
            System.out.println(encAesSecretKey);
            System.out.println(">>>>>>>>>>>>>>>>>>>>>> final save key >>>> ee");
            
            //logger.debug("exChangeKeyHex id[{}]key[{}]", id, encAesSecretKey);
            
        }
        catch (InvalidKeyException e) {
            //if (logger.isDebugEnabled()) {
                e.printStackTrace();
            //}
            //throw new ServerException(ErrorConstant.E2E_KEY_EXCHANGE, e);
        }
        catch (IllegalStateException e) {
            //if (logger.isDebugEnabled()) {
                e.printStackTrace();
            //}
            //throw new ServerException(ErrorConstant.E2E_KEY_EXCHANGE, e);
        }
        catch (NoSuchAlgorithmException e) {
            //if (logger.isDebugEnabled()) {
                e.printStackTrace();
            //}
            //throw new ServerException(ErrorConstant.E2E_KEY_EXCHANGE, e);
        }
        catch (InvalidAlgorithmParameterException e) {
            //if (logger.isDebugEnabled()) {
                e.printStackTrace();
            //}
            //throw new ServerException(ErrorConstant.E2E_KEY_EXCHANGE, e);
        }
        catch (InvalidKeySpecException e) {
            //if (logger.isDebugEnabled()) {
                e.printStackTrace();
            //}
            //throw new ServerException(ErrorConstant.E2E_KEY_EXCHANGE, e);
        }
        catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return serverPublicKey;
    }
    
    private byte[] encryptHMAC(String id, byte[] sourceMessage) {
        String encKey = getKey(id);
        byte[] bResultMessage = null;
        
        if (StringUtils.isEmpty(encKey)) {
            //throw new ServerException(ErrorConstant.E2E_KEY_NOT_EXIST, sourceMessage);
        }
        else {
            // 생성되어 있는 키가 있다면, 30 분 갱신
            //e2eKeyRepository.set(id, encKey, 30, TimeUnit.MINUTES);
        }
        
        try {
            //logger.debug("encKey [{}]", encKey);
            
            String sSourceMessage = new String(sourceMessage);
            //logger.debug("sSourceMessage:[{}]", sSourceMessage);
            String timestamp = String.valueOf(System.currentTimeMillis());
            
            String hmac = SecurityHashUtils.hmac(timestamp, sSourceMessage, encKey);
            
            String sMessage = AesUtils.encrypt(encKey, timestamp + "." + sSourceMessage);
            
            //logger.debug("sMessage encoded:[{}]", sMessage);
            //logger.debug("timestamp:[{}]", timestamp);
            //logger.debug("hmac:[{}]", hmac);
            
            String sResultMessage = sMessage + "." + timestamp + "." + hmac;
            
            bResultMessage = sResultMessage.getBytes();
        }
        catch (Exception ex) {
            //logger.error(ExceptionUtils.getStackTrace(ex));
            //throw new ServerException(ErrorConstant.E2E_ENCODE_ERROR, ex, sourceMessage);
        }
        return bResultMessage;
    }
    
    private byte[] decryptHMAC(String id, byte[] bSourceMessage) {
        // 2015-08-25
        // hmac, timestemp 적용
        // 원본메세지.timestamp.hmac
        String sSourceMessage = new String(bSourceMessage);
        System.out.println("sSourceMssage:" + sSourceMessage);
        
        // format check
        if (!StringUtils.contains(sSourceMessage, ".")) {
            //throw new ServerException(ErrorConstant.E2E_DECODE_FORMAT_ERROR, bSourceMessage);
        }
        
        String[] arrMessage = StringUtils.split(sSourceMessage, ".");
        
        if (arrMessage == null || arrMessage.length != 3) {
            //throw new ServerException(ErrorConstant.E2E_DECODE_FORMAT_ERROR, bSourceMessage);
        }
        
        String messagePart = arrMessage[0];
        String timestampPart = arrMessage[1];
        String hmacPart = arrMessage[2];
        
        if (StringUtils.isEmpty(messagePart) || StringUtils.isEmpty(timestampPart) || StringUtils.isEmpty(hmacPart)) {
            //throw new ServerException(ErrorConstant.E2E_DECODE_FORMAT_ERROR, bSourceMessage);
        }
        
        //logger.debug("messagePart:[{}]", messagePart);
        //logger.debug("timestampPart:[{}]", timestampPart);
        //logger.debug("hmacPart:[{}]", hmacPart);
        
        String decKey = getKey(id);
        byte[] bDecodedMessage = null;
        
        if (StringUtils.isEmpty(decKey)) {
           // throw new ServerException(ErrorConstant.E2E_KEY_NOT_EXIST);
        }
        
        try {
            //logger.debug("decKey [{}]", decKey);
            String sDecodeMessage = AesUtils.decrypt(decKey, messagePart);
           // logger.debug("sDecodeMessage:[{}]", sDecodeMessage);
            String timestampInMessage = StringUtils.substringBeforeLast(sDecodeMessage, ".");
            String sResultMessage = StringUtils.substringAfterLast(sDecodeMessage, ".");
            
            //logger.debug("sResultMessage:[{}]", sResultMessage);
            //logger.debug("timestampInMessage:[{}]", timestampInMessage);
            
            String hmac = SecurityHashUtils.hmac(timestampInMessage, sResultMessage, decKey);
            
            //logger.debug("cal hmac:[{}]", hmac);
            
            // hmac check
            if (!hmacPart.equals(hmac)) {
                //throw new ServerException(ErrorConstant.E2E_DECODE_HMAC_ERROR, bSourceMessage);
            }
            
            // timestamp eq check
            if (!timestampPart.equals(timestampInMessage)) {
                //throw new ServerException(ErrorConstant.E2E_DECODE_TIMESTAMP_NOT_EQUAL_ERROR, bSourceMessage);
            }
            
            // timestamp valid check
            long diffTimestamp = System.currentTimeMillis() - Long.valueOf(timestampInMessage);
            long vaildDiffTimestamp = 5 * 60 * 1000; // 5 min
            if (Math.abs(diffTimestamp) > vaildDiffTimestamp) {
                //throw new ServerException(ErrorConstant.E2E_DECODE_TIMESTAMP_INVALID_ERROR, bSourceMessage);
            }
            
            bDecodedMessage = sResultMessage.getBytes();
            
        }
        catch (Exception ex) {
            //logger.error(ExceptionUtils.getStackTrace(ex));
            //throw new ServerException(ErrorConstant.E2E_DECODE_ERROR, ex, bSourceMessage);
        }
        return bDecodedMessage;
    }

	@Override
	public String getCertData() {

		throw new UnsupportedOperationException();
	}

	@Override
	public boolean encryptFile(final String id, final String sourceFilename, final String targetFilename) {

		final String key = getKey(id);
		if (key == null) {
			//throw new ServerException(ErrorConstant.E2E_KEY_NOT_EXIST);
		}

		final String zipPasswd = StringUtils.left(key, 16);
		AesUtils.executeFile(Cipher.ENCRYPT_MODE, sourceFilename, targetFilename, zipPasswd);

		return true;
	}
}