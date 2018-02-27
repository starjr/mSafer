package com.example.demo.service;

import org.springframework.stereotype.Service;

public interface E2EService {

    String getServerPublicKey(String id, String clientPublicKey);
    
    String getKey(String id);
    
    byte[] encrypt(String id, byte[] sourceMessage);
    
    byte[] decrypt(String id, byte[] sourceMessage);
    
    String getServerPublicKeyHex(String id, String clientPublicKey);
    
    String getCertData();
    
    boolean encryptFile(final String id, final String sourceFilename, final String targetFilename);
}
