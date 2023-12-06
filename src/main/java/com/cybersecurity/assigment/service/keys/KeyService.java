package com.cybersecurity.assigment.service.keys;

import com.cybersecurity.assigment.model.user.User;
import com.cybersecurity.assigment.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Optional;

@Service
public class KeyService {
    @Autowired
    private UserRepository userRepository;

    public KeyPair saveRSAKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = new SecureRandom();
        keyPairGenerator.initialize(2048, secureRandom);

        return keyPairGenerator.generateKeyPair();

    }
    public SecretKey saveAESKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        File secretKeyFile = new File("secret.key");

        if(!secretKeyFile.exists()){
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();

            try (FileOutputStream fos = new FileOutputStream(secretKeyFile)) {
                fos.write(secretKey.getEncoded());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return secretKey;
        }

        else return null;
    }
    public PublicKey getPublicKey(String username) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        Optional<User> user= userRepository.findByUsername(username);
        byte[] publicKeyBytes = user.get().getPublicKey();

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey= keyFactory.generatePublic(publicKeySpec);

        return publicKey;
    }

    public PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        Optional<User> user= userRepository.findByUsername(username);
        byte[] privateKeyBytes = user.get().getPrivateKey();

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

    public byte[] asymmetricDecryption(byte[] data, String username) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        PublicKey publicKey = getPublicKey(username);
        Cipher cipher = Cipher.getInstance("RSA");

        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] plainData = cipher.doFinal(data);

        return plainData;
    }

    public byte[] symmetricEncryption(byte[] data, IvParameterSpec ivParameterSpec) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        saveAESKey();
        SecretKey secretKey = getSecretKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);


        byte[] encryptedData = cipher.doFinal(data);

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

