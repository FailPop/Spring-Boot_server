package com.mvas.server.controller;

import com.puppycrawl.tools.checkstyle.Checker;
import com.puppycrawl.tools.checkstyle.ConfigurationLoader;
import com.puppycrawl.tools.checkstyle.PropertiesExpander;
import com.puppycrawl.tools.checkstyle.api.AuditEvent;
import com.puppycrawl.tools.checkstyle.api.AuditListener;
import com.puppycrawl.tools.checkstyle.api.CheckstyleException;
import com.puppycrawl.tools.checkstyle.api.Configuration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@RestController
public class ServerController {

    private static final Logger logger = LogManager.getLogger(ServerController.class);

    private RSAPrivateKey serverPrivateKey;
    private RSAPublicKey serverPublicKey;

    private RSAPublicKey clientPublicKey;

    @PostMapping("/receiveClientPublicKey")
    public void receiveClientPublicKey(@RequestBody String publicKey) throws Exception {
        this.clientPublicKey = decodeRSAPublicKey(publicKey);
    }

    public ServerController() throws NoSuchAlgorithmException {
        logger.info("GenerateRSAKeyPair");
        KeyPair keyPair = generateRSAKeyPair();
        serverPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        serverPublicKey = (RSAPublicKey) keyPair.getPublic();
    }

    @PostMapping("/getServerPublicKey")
    public String getServerPublicKey() {
        logger.info("GetServerPublicKey");
        return Base64.getEncoder().encodeToString(serverPublicKey.getEncoded());
    }

    @PostMapping("/receiveEncryptedData")
    public String receiveEncryptedData(@RequestBody String encryptedData) {
        try {
            logger.info("ReceiveEncryptedData");
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

            Path file = Paths.get("src/main/resources/clientcode.java");
            Files.write(file, decryptedMessage);

            // Анализ файла с использованием Checkstyle
            String errors = analyzeCheckstyle(file);

            // Шифрование ошибок с помощью AES и RSA
            String encryptedErrors = encryptWithClientPublicKey(errors);

            return encryptedErrors;

        } catch (Exception e) {
            return "Unexpected error, please write your code";
        }
    }
    private String encryptWithClientPublicKey(String message) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedMessage = aesCipher.doFinal(message.getBytes(StandardCharsets.UTF_8));

        Cipher rsaCipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        return Base64.getEncoder().encodeToString(encryptedAesKey) + ":" + Base64.getEncoder().encodeToString(encryptedMessage);
    }

    private String analyzeCheckstyle(Path filePath) throws IOException, CheckstyleException {
        // Загрузка конфигурации Checkstyle из ресурсов
        Configuration config = ConfigurationLoader.loadConfiguration("src/main/resources/checkstyle-config.xml", new PropertiesExpander(System.getProperties()));

        // Инициализация Checker
        Checker checker = new Checker();
        checker.setModuleClassLoader(Thread.currentThread().getContextClassLoader());
        checker.configure(config);

        // Создание списка для сообщений об ошибках
        List<String> errorMessages = new ArrayList<>();

        // Создание слушателя событий аудита
        AuditListener listener = new AuditListener() {
            @Override
            public void auditStarted(AuditEvent event) {
            }

            @Override
            public void auditFinished(AuditEvent event) {
            }

            @Override
            public void fileStarted(AuditEvent event) {
            }

            @Override
            public void fileFinished(AuditEvent event) {
            }

            @Override
            public void addError(AuditEvent event) {
                errorMessages.add("Error: " + event.getMessage() + ", line: " + event.getViolation().getLineNo() + ", column: " + event.getViolation().getColumnNo());
            }

            @Override
            public void addException(AuditEvent event, Throwable throwable) {
                errorMessages.add("Exception: " + event.getMessage());
            }
        };

        // Добавление слушателя к Checker
        checker.addListener(listener);

        // Анализ файла
        checker.process(List.of(filePath.toFile()));

        // Сбор сообщений об ошибках в строку
        StringBuilder errorList = new StringBuilder();
        for (String errorMessage : errorMessages) {
            errorList.append(errorMessage).append("\n");
        }

        return errorList.toString();
    }


    private RSAPublicKey decodeRSAPublicKey(String publicKeyBase64) throws Exception {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        logger.info("GenerateRSAKeyPair");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
}
