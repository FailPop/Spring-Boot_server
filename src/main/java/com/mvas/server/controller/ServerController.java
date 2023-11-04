package com.mvas.server.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

@RestController
public class ServerController {

    private RSAPrivateKey serverPrivateKey;
    private RSAPublicKey serverPublicKey;

    public ServerController() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRSAKeyPair();
        serverPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        serverPublicKey = (RSAPublicKey) keyPair.getPublic();
    }

    @PostMapping("/receivePublicKey")
    public String receivePublicKey(@RequestBody String publicKeyBase64) {
        try {
            return Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @PostMapping("/getServerPublicKey")
    public String getServerPublicKey() {
        return Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
    }

    @PostMapping("/receiveMessage")
    public String receiveMessage(@RequestBody String encryptedMessage) {
        try {
            String decryptedMessage = decryptWithServerPrivateKey(encryptedMessage);

            String response = "Accept: " + decryptedMessage;
            return response;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private String decryptWithServerPrivateKey(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, "UTF-8"); // Указываем кодировку UTF-8
    }
}
