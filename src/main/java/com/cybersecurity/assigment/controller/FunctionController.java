package com.cybersecurity.assigment.controller;

import com.cybersecurity.assigment.model.file.FileModel;
import com.cybersecurity.assigment.repository.FileRepository;
import com.cybersecurity.assigment.service.files.FilesStorageService;
import com.cybersecurity.assigment.service.keys.KeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

@Controller
public class FunctionController {
    @Autowired
    FileRepository fileRepository;
    @Autowired
    FilesStorageService storageService;

    @Autowired
    KeyService keyService;

    //Page to sign file
    @RequestMapping("/sign/{id}")
    public String sign(@PathVariable Integer id, Model model) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, InvalidKeyException {
        //Getting file from its unique id;
        FileModel file = storageService.getFile(id);

        //Hashing method is determined(SHA-512 is selected by me)
        MessageDigest md = MessageDigest.getInstance("SHA-512");

        //File's data bytes is given as an input for hashing;
        md.update(file.getData());

        //Getting hashed value of data
        byte[] hashedData = md.digest();

        //To sign, hashed data is given to asymmetricEncryption function which is I've created.
        //RSA algorithm is used for asymmetric encryption
        //Note: Details is given in KeyService class
        byte[] signedData = keyService.asymmetricEncryption(hashedData);

        //Updating signed entity of file to new signed value in database
        file.setSigned(signedData);
        fileRepository.save(file);

        //Showing digital signature value
        model.addAttribute("value", Base64.getEncoder().encodeToString(signedData));
       return "signed";
    }

    //Page to verify file(confirmation of signature)
    @RequestMapping("/verify/{id}")
    public String verifyFile(@PathVariable Integer id, Model model) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        //Getting file from its unique id;
        FileModel file = storageService.getFile(id);

        //Getting signed data of file from database
        byte[] signedData = file.getSigned();

        //Hashing is used for checking validate signature
        //Hashing method is determined(SHA-512 is selected by me)
        MessageDigest md = MessageDigest.getInstance("SHA-512");

        //Getting hashed value of data
        md.update(file.getData());
        byte[] bytes = md.digest();

        //Signed data is given to asymmetricDecryption for getting decrypted data.
        //Note: Details is given in KeyService class
        byte[] decryptedData = keyService.asymmetricDecryption(signedData, file.getPublisher());

        //Checking equality between decrypted data and hashed value of original data.
        //If they are equal, user confirms the file is come from actual user.
        if(Base64.getEncoder().encodeToString(decryptedData).equals(Base64.getEncoder().encodeToString(bytes)))
        {
            model.addAttribute("value", "Verified by : " + file.getPublisher());
        } else model.addAttribute("value", "Not verified.");

        return "verify";
    }

    //Page to encrypt file symmetrically
    @RequestMapping("/encrypt/{id}")
    public String symmetricEncryption(@PathVariable Integer id, Model model) throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        //Getting file from its unique id;
        FileModel file = storageService.getFile(id);

        //Ivparameter is used for padding in encryption
        IvParameterSpec ivParameterSpec = keyService.generateIv();

        //To encrypt, data is given to symmetricEncryption function which is I've created.
        //AES algorithm is used for symmetric encryption
        //Note: Details is given in KeyService class
        byte[] encryptedData = keyService.symmetricEncryption(file.getData(), ivParameterSpec);

        //Updating encrypted entity of file to new encrypted data in database
        file.setEncrypted(encryptedData);
        fileRepository.save(file);

        model.addAttribute("value", encryptedData);
        return "encrypted";
    }

    @RequestMapping("/decrypt/{id}")
    public ResponseEntity<byte[]> symmetricDecryption(@PathVariable Integer id) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
        //Getting file from its unique id;
        FileModel file = storageService.getFile(id);

        //Getting encrypted data of file from database
        byte[] encryptedData = file.getEncrypted();

        //Ivparameter is used for unpadding in decryption
        IvParameterSpec ivParameterSpec = keyService.generateIv();

        //To decrypt, data is given to symmetricDecryption function which is I've created.
        //Note: Details is given in KeyService class
        byte[] decryptedData = keyService.symmetricDecryption(encryptedData, ivParameterSpec);

        //Returning file in response entity so we can read file
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"")
                .body(decryptedData);
    }
}
