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

        @Autowired
        FilesStorageService storageService;

        @PostMapping("/upload")
        public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
            String message = "";
            if(!file.isEmpty()) {
                try {
                    storageService.save(file);

                    message = "Uploaded the file successfully: " + file.getOriginalFilename();
                    return ResponseEntity.status(HttpStatus.OK).body(message);
                } catch (Exception e) {
                    message = "Could not upload the file: " + file.getOriginalFilename() + ". Error: " + e.getMessage();
                    return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(message);
                }
            }
            message = "Such file does not exist: " + file.getContentType();
            return ResponseEntity.status(HttpStatus.EXPECTATION_FAILED).body(message);
        }

        @GetMapping("/files")
        public ResponseEntity<List<FileInfo>> getListFiles() {
            List<FileInfo> fileInfos = storageService.getAllFiles().map(dbFile -> {
                String fileUri = ServletUriComponentsBuilder.fromCurrentContextPath()
                        .path("/files/")
                        .path(String.valueOf(dbFile.getId()))
                        .toUriString();

                return new FileInfo(dbFile.getName(), dbFile.getType(), dbFile.getData(), fileUri);
            }).collect(Collectors.toList());

            return ResponseEntity.status(HttpStatus.OK).body(fileInfos);
        }

        @GetMapping("/")
        public String getAllFileInfos(Model model)
        {
            model.addAttribute("senderFiles", storageService.getAllFilesByPublisher());
            model.addAttribute("receiverFiles", storageService.getAllReceiverFiles());
            model.addAttribute("username", SecurityContextHolder.getContext().getAuthentication().getName());
            return "index";
        }

        @GetMapping("/file/{id}")
        @ResponseBody
        public ResponseEntity<byte[]> getFile(@PathVariable Integer id) {
            FileModel file = storageService.getFile(id);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"")
                    .body(file.getData());
        }

}
