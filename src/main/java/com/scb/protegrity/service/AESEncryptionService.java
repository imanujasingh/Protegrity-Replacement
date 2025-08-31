package com.scb.protegrity.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
@Slf4j
public class AESEncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private final SecretKey secretKey;
    private final SecureRandom secureRandom;

    public AESEncryptionService(@Value("${aes.encryption.key}") String base64Key) {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        this.secretKey = new SecretKeySpec(decodedKey, "AES");
        this.secureRandom = new SecureRandom();
        log.info("AESEncryptionService initialized successfully");
    }

    public String encrypt(String plaintext) throws Exception {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] cipherTextBytes = cipher.doFinal(plaintext.getBytes());

            byte[] encryptedData = new byte[iv.length + cipherTextBytes.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(cipherTextBytes, 0, encryptedData, iv.length, cipherTextBytes.length);

            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            log.error("Encryption failed for text: {}", plaintext, e);
            throw new Exception("Encryption failed: " + e.getMessage());
        }
    }

    public String decrypt(String base64CipherText) throws Exception {
        try {
            byte[] encryptedData = Base64.getDecoder().decode(base64CipherText);

            byte[] iv = new byte[IV_LENGTH_BYTE];
            System.arraycopy(encryptedData, 0, iv, 0, iv.length);

            int cipherTextLength = encryptedData.length - IV_LENGTH_BYTE;
            byte[] cipherTextBytes = new byte[cipherTextLength];
            System.arraycopy(encryptedData, IV_LENGTH_BYTE, cipherTextBytes, 0, cipherTextLength);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            byte[] decryptedBytes = cipher.doFinal(cipherTextBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            log.error("Decryption failed for ciphertext: {}", base64CipherText, e);
            throw new Exception("Decryption failed: " + e.getMessage());
        }
    }
}
