package com.thebodgeitstore.util;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_TYPE = "AES";
    private static final int KEY_SIZE_BITS = 256;
    private static final int GCM_NONCE_LENGTH = 12; // 96 bits for GCM
    private static final int GCM_TAG_LENGTH = 128;  // bits
    private static final int PBKDF2_ITERATIONS = 100000;
    
    private SecretKey key;
    private final SecureRandom secureRandom;
    private byte[] nonce;
     
    public AES() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, 
            InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {
        KeyGenerator kgen = KeyGenerator.getInstance(KEY_TYPE);
        kgen.init(KEY_SIZE_BITS);
        key = kgen.generateKey();
        secureRandom = new SecureRandom();
        nonce = new byte[GCM_NONCE_LENGTH];
        secureRandom.nextBytes(nonce);
    }
    
    public String getIVAsHex() {
        return byteArrayToHexString(nonce);
    }
    
    public String getKeyAsHex() {
        return byteArrayToHexString(key.getEncoded());
    }
    
    public void setCrtKey(String keyText) throws InvalidKeyException, NoSuchAlgorithmException {
        // Use PBKDF2 for key derivation instead of the previous insecure method
        byte[] salt = new byte[16];
        secureRandom.nextBytes(salt);
        
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(keyText.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE_BITS);
        
        try {
            SecretKey tmp = factory.generateSecret(spec);
            key = new SecretKeySpec(tmp.getEncoded(), KEY_TYPE);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to derive key", e);
        }
    }
    
    public void setStringToKey(String keyText) throws NoSuchAlgorithmException {
        setKey(keyText.getBytes(StandardCharsets.UTF_8));
    }
    
    public void setHexToKey(String hexKey) {
        setKey(hexStringToByteArray(hexKey));
    }
    
    private void setKey(byte[] bArray) {
        byte[] bText = new byte[KEY_SIZE_BITS/8];
        int end = Math.min(KEY_SIZE_BITS/8, bArray.length);
        System.arraycopy(bArray, 0, bText, 0, end);
        key = new SecretKeySpec(bText, KEY_TYPE);
    }
    
    public void setStringToIV(String ivText) {
        setIV(ivText.getBytes(StandardCharsets.UTF_8));
    }
    
    public void setHexToIV(String hexIV) {
        setIV(hexStringToByteArray(hexIV));
    }
    
    private void setIV(byte[] bArray) {
        nonce = new byte[GCM_NONCE_LENGTH];
        int end = Math.min(GCM_NONCE_LENGTH, bArray.length);
        System.arraycopy(bArray, 0, nonce, 0, end);
    }
        
    public String encryptCRT(String message) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, 
            NoSuchPaddingException {
        // Generate a new nonce for each encryption
        nonce = new byte[GCM_NONCE_LENGTH];
        secureRandom.nextBytes(nonce);
        
        String hexMessage = encrypt(message);
        return byteArrayToHexString(nonce).concat(hexMessage.substring(2));
    }
    
    public String encrypt(String message) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
        
        byte[] encrypted = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return byteArrayToHexString(encrypted);
    }
    
    public String decryptCrt(String hexCipherText) throws InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, 
            BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] ciphertextBytes = hexStringToByteArray(hexCipherText);
        
        // Extract nonce from ciphertext
        nonce = Arrays.copyOf(ciphertextBytes, GCM_NONCE_LENGTH);
        
        // Decrypt the rest of the message
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        
        byte[] recoveredCleartext = cipher.doFinal(ciphertextBytes, GCM_NONCE_LENGTH, 
                ciphertextBytes.length - GCM_NONCE_LENGTH);
        return new String(recoveredCleartext, StandardCharsets.UTF_8);
    }
    
    public String decrypt(String hexCiphertext)
            throws IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] cipherText = hexStringToByteArray(hexCiphertext);
        
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        
        byte[] decrypted = cipher.doFinal(cipherText);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
         
    private static String byteArrayToHexString(byte[] raw) {
        StringBuilder sb = new StringBuilder(2 + raw.length * 2);
        sb.append("0x");
        for (int i = 0; i < raw.length; i++) {
            sb.append(String.format("%02X", Integer.valueOf(raw[i] & 0xFF)));
        }
        return sb.toString();
    }
    
    private static byte[] hexStringToByteArray(String hex) {
        Pattern replace = Pattern.compile("^0x");
        String s = replace.matcher(hex).replaceAll("");
        
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            int index = i * 2;
            int v = Integer.parseInt(s.substring(index, index + 2), 16);
            b[i] = (byte)v;
        }
        return b;
    }
}