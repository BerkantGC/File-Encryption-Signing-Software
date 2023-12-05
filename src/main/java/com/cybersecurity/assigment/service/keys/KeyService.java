package com.cybersecurity.assigment.service.keys;

import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

@Service
public class KeyService {
    private static final int IV_LENGTH = 12;

    public KeyPair saveRSAKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom();
        keyPairGenerator.initialize(2048, secureRandom);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        try (FileOutputStream fos = new FileOutputStream("public.key")) {
            fos.write(publicKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try (FileOutputStream fos = new FileOutputStream("private.key")) {
            fos.write(privateKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return keyPair;
    }
    public SecretKey saveAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        try (FileOutputStream fos = new FileOutputStream("secret.key")) {
            fos.write(secretKey.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return secretKey;
    }
    public PublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File publicKeyFile = new File("public.key");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey= keyFactory.generatePublic(publicKeySpec);

        return publicKey;
    }

    public PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File privateKeyFile = new File("private.key");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return privateKey;
    }

    public SecretKey getSecretKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File secretKeyFile = new File("secret.key");
        byte[] secretKeyBytes = Files.readAllBytes(secretKeyFile.toPath());

        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");
        return  secretKey;
    }

    public byte[] asymmetricEncryption(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        PrivateKey privateKey = getPrivateKey();
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        cipher.update(data);
        byte[] cipherData = cipher.doFinal();

        return cipherData;
    }

    public byte[] asymmetricDecryption(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        PublicKey publicKey = getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] plainData = cipher.doFinal(data);

        return plainData;
    }

    public byte[] symmetricEncryption(byte[] data, IvParameterSpec ivParameterSpec) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        SecretKey secretKey = getSecretKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);


        byte[] encryptedData = cipher.doFinal(data);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] plainData = cipher.doFinal(encryptedData);

        return encryptedData;
    }
    public byte[] symmetricDecryption(byte[] data, IvParameterSpec ivParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        SecretKey secretKey = getSecretKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");


        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] plainData = cipher.doFinal(data);

        return plainData;
    }
    public IvParameterSpec generateIv() {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0 };
        return new IvParameterSpec(iv);
    }
}

