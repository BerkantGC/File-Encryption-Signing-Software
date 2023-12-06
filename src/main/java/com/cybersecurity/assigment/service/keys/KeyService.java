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

//Service for key operations
@Service
public class KeyService {
    @Autowired
    private UserRepository userRepository;

    //Function to generate IVParameterSpec to use for padding and unpadding in symmetrically encryption
    public IvParameterSpec generateIv() {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0 };
        return new IvParameterSpec(iv);
    }

    //RSA Key Generator
    public KeyPair generateRSAKey() throws NoSuchAlgorithmException {
        //Defining encryption algorithm for generating keypair
        //RSA is used
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        //Generating secure random to get random keypair
        SecureRandom secureRandom = new SecureRandom();

        //initializing new random 2040 byte keypair
        keyPairGenerator.initialize(2048, secureRandom);

        return keyPairGenerator.generateKeyPair();

    }
    public SecretKey saveAESKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        //To check secret key is already exist
        File secretKeyFile = new File("secret.key");

        if(!secretKeyFile.exists()){ //if it does not exist, create a new key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

            //initializing new random 256 byte key
            keyGenerator.init(256);
            SecretKey secretKey = keyGenerator.generateKey();

            //save to file
            try (FileOutputStream fos = new FileOutputStream(secretKeyFile)) {
                fos.write(secretKey.getEncoded());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return secretKey;
        }

        //if it already exists, do nothing
        else return null;
    }
    public PublicKey getPublicKey(String username) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Optional<User> user= userRepository.findByUsername(username);

        //Get public key bytes of given user
        byte[] publicKeyBytes = user.get().getPublicKey();

        //Convert bytes to key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PublicKey publicKey= keyFactory.generatePublic(publicKeySpec);

        return publicKey;
    }

    public PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        Optional<User> user= userRepository.findByUsername(username);

        //Get private key bytes of current user
        byte[] privateKeyBytes = user.get().getPrivateKey();

        //Convert bytes to key
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return privateKey;
    }

    public SecretKey getSecretKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //Get secret key bytes from file
        File secretKeyFile = new File("secret.key");
        byte[] secretKeyBytes = Files.readAllBytes(secretKeyFile.toPath());

        //Convert bytes to key
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");
        return  secretKey;
    }

    //Function to encrypt the data asymmetrically
    public byte[] asymmetricEncryption(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        //Getting private key of current user
        PrivateKey privateKey = getPrivateKey();

        //RSA algorithm is used for asymmetric encryption
        Cipher cipher = Cipher.getInstance("RSA");

        //initializing the cipher with private key in encrypt mode
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        //Getting encrypted data
        cipher.update(data);
        byte[] encryptedData = cipher.doFinal();

        return encryptedData;
    }

    //Function to decrypt the data asymmetrically
    public byte[] asymmetricDecryption(byte[] data, String username) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        //Getting public key of file's publisher
        PublicKey publicKey = getPublicKey(username);

        //RSA algorithm is used for asymmetric decryption
        Cipher cipher = Cipher.getInstance("RSA");

        //initializing the cipher with public key in decrypt mode
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        //Getting decrypted data
        byte[] decryptedData = cipher.doFinal(data);

        return decryptedData;
    }

    //Function to decrypt the data symmetrically
    public byte[] symmetricEncryption(byte[] data, IvParameterSpec ivParameterSpec) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        //Generating and save new AES secret key if it doesn't exist
        saveAESKey();

        //Getting secret key
        SecretKey secretKey = getSecretKey();

        //AES algorithm is used for symmetric encryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //initializing the cipher with secret key and ivParameterSpec for padding in encrypt mode
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        //Getting symmetrically encrypted data
        byte[] encryptedData = cipher.doFinal(data);

        return encryptedData;
    }
    public byte[] symmetricDecryption(byte[] data, IvParameterSpec ivParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        //Getting secret key
        SecretKey secretKey = getSecretKey();

        //AES algorithm is given to cipher
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //initializing the cipher with same secret key and same ivParameterSpec in decrypt mode
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        //Getting asymmetrically decrypted data
        byte[] plainData = cipher.doFinal(data);

        return plainData;
    }
}

