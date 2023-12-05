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

    @RequestMapping("/sign/{id}")
    public String sign(@PathVariable Integer id, Model model) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException, InvalidKeyException {
        FileModel file = storageService.getFile(id);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(file.getData());

        byte[] bytes = md.digest();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        String hashedValue = sb.toString();


        byte[] cipherData = keyService.asymmetricEncryption(bytes);

        file.setSigned(cipherData);
        fileRepository.save(file);

        model.addAttribute("value", Base64.getEncoder().encodeToString(cipherData));
       return "signed";
    }

    @RequestMapping("/verify/{id}")
    public String verifyFile(@PathVariable Integer id, Model model) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {
        FileModel file = storageService.getFile(id);

        byte[] cipherData = file.getSigned();

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(file.getData());

        byte[] bytes = md.digest();

        byte[] decryptedData = keyService.asymmetricDecryption(cipherData);


        if(Base64.getEncoder().encodeToString(decryptedData).equals(Base64.getEncoder().encodeToString(bytes)))
        {
            model.addAttribute("value", "Verified");
        }

        return "signed";
    }

    @RequestMapping("/encrypt/{id}")
    public String symmetricEncryption(@PathVariable Integer id) throws IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        FileModel file = storageService.getFile(id);
        IvParameterSpec ivParameterSpec = keyService.generateIv();

        byte[] encryptedData = keyService.symmetricEncryption(file.getData(), ivParameterSpec);

        file.setEncrypted(encryptedData);
        fileRepository.save(file);
        return "encrypted";
    }

    @RequestMapping("/decrypt/{id}")
    public ResponseEntity<byte[]> symmetricDecryption(@PathVariable Integer id) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
        FileModel file = storageService.getFile(id);

        byte[] encryptedData = file.getEncrypted();
        IvParameterSpec ivParameterSpec = keyService.generateIv();

        byte[] decryptedData = keyService.symmetricDecryption(encryptedData, ivParameterSpec);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"")
                .body(decryptedData);
    }
}
