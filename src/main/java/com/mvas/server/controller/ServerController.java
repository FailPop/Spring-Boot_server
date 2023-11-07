package com.mvas.server.controller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@RestController
public class ServerController {

    private RSAPrivateKey serverPrivateKey;
    private RSAPublicKey serverPublicKey;

    public ServerController() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRSAKeyPair();
        serverPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        serverPublicKey = (RSAPublicKey) keyPair.getPublic();
    }

    @PostMapping("/getServerPublicKey")
    public String getServerPublicKey() {
        return Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
    }

    @PostMapping("/receiveEncryptedData")
    public String receiveEncryptedData(@RequestBody String encryptedData) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            String[] parts = encryptedData.split(":");

            Cipher rsaCipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] encryptedAesKey = Base64.getDecoder().decode(parts[0]);
            byte[] decryptedAesKey = rsaCipher.doFinal(encryptedAesKey);

            SecretKeySpec aesKey = new SecretKeySpec(decryptedAesKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] encryptedMessage = Base64.getDecoder().decode(parts[1]);
            byte[] decryptedMessage = aesCipher.doFinal(encryptedMessage);

            return new String(decryptedMessage, "UTF-8");
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
}
