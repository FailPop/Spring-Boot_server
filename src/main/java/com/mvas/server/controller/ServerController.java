package com.mvas.server.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;

@RestController
public class ServerController {
    private static final Logger logger = LogManager.getLogger(ServerController.class);
    private RSAPrivateKey serverPrivateKey;
    private RSAPublicKey serverPublicKey;

    public ServerController() throws NoSuchAlgorithmException {
        logger.info("Generation KeyPair");
        KeyPair keyPair = generateRSAKeyPair();
        serverPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        serverPublicKey = (RSAPublicKey) keyPair.getPublic();
        logger.info("Public Key: " + serverPublicKey);
        logger.info("Private Key: " + serverPrivateKey);
    }

    @PostMapping("/receivePublicKey")
    public String receivePublicKey(@RequestBody String publicKeyBase64) {
        try {
            logger.info("Reseive Public Key: " + publicKeyBase64);
            return Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @PostMapping("/getServerPublicKey")
    public String getServerPublicKey() {
        logger.info("Get Server Public Key");
        return Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
    }

    @PostMapping("/receiveFile")
    public String receiveFile(@RequestBody List<String> encryptedBlocks) {
        try {
            StringBuilder decryptedMessage = new StringBuilder();
            for (String encryptedBlock : encryptedBlocks) {
                decryptedMessage.append(decryptWithServerPrivateKey(encryptedBlock));
            }
            // Здесь вы можете обработать расшифрованное сообщение, например, сохранить его в файл
            return "File received and decrypted: " + decryptedMessage;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        logger.info("Generate RSA Key Pair");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        logger.info("KeyGen: "+ keyGen);
        return keyGen.generateKeyPair();
    }

    private String decryptWithServerPrivateKey(String encryptedMessage) throws Exception {
        logger.info("Decrypt With Server Private Key");
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        logger.info("Decrypted Bytes: " + decryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8); // Указываем кодировку
    }
}
