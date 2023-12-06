package com.cybersecurity.assigment.controller;

import com.cybersecurity.assigment.model.file.FileInfo;
import com.cybersecurity.assigment.model.file.FileModel;
import com.cybersecurity.assigment.service.files.FilesStorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.List;
import java.util.stream.Collectors;
 @Controller
    public class FilesController {
        //"Autowired" that enables dependency injection for Java classes in Spring Framework .
        @Autowired
        FilesStorageService storageService;

        @PostMapping("/upload")
        public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
            String message = "";
            if(!file.isEmpty()) {
                try {
                    storageService.save(file); //Saving file to database

                    message = "Uploaded the file successfully: " + file.getOriginalFilename(); //Message after a successful upload
                    return ResponseEntity.status(HttpStatus.OK).body(message);
                } catch (Exception e) {
                    message = "Could not upload the file: " + file.getOriginalFilename() + ". Error: " + e.getMessage(); //Error while uploading the file
                    return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(message);
                }
            }
            message = "Such file does not exist: " + file.getContentType(); //File is not uploaded
            return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(message);
        }

        @GetMapping("/files")
        public ResponseEntity<List<FileInfo>> getListFiles() {
            // Creating uri for all files
            List<FileInfo> fileInfos = storageService.getAllFiles().map(dbFile -> {
                String fileUri = ServletUriComponentsBuilder.fromCurrentContextPath()
                        .path("/files/")
                        .path(String.valueOf(dbFile.getId()))
                        .toUriString();

            // Getting the information as response to show as API (This isn't included to project)
                return new FileInfo(dbFile.getName(), dbFile.getType(), dbFile.getData(), fileUri);
            }).collect(Collectors.toList());

            // Show all files in API
            return ResponseEntity.status(HttpStatus.OK).body(fileInfos);
        }

        @GetMapping("/")
        public String getAllFileInfos(Model model)
        {
            //All files owned by the current user
            model.addAttribute("senderFiles", storageService.getAllFilesByPublisher());

            //All files owned by other users except the current user
            model.addAttribute("receiverFiles", storageService.getAllReceiverFiles());

            //The username of the current user will be displayed on main page
            model.addAttribute("username", SecurityContextHolder.getContext().getAuthentication().getName());
            return "index";
        }
}
