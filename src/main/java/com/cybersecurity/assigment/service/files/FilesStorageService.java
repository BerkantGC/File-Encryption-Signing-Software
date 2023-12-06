package com.cybersecurity.assigment.service.files;

import com.cybersecurity.assigment.model.file.FileModel;
import com.cybersecurity.assigment.repository.FileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOError;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

//Service is for file storage operations
@Service
public class FilesStorageService{
    @Autowired
    private FileRepository fileRepository;

    //Function for saving new file to database
    public FileModel save(MultipartFile file /*Getting file as parameter*/) throws IOException{
        //Getting original name from file
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());

        //Creating file model to save
        FileModel fileModel = new FileModel(
                fileName, //name
                file.getContentType(), //type
                file.getBytes(), //data
                null, //signature
                null, //encrypted data
                //User who uploaded file is the publisher of file
                SecurityContextHolder.getContext().getAuthentication().getName());


        return fileRepository.save(fileModel);
    }

    public FileModel getFile(Integer id)
    {
        //Getting file with its unique id from database
        return fileRepository.findById(id.longValue()).get();
    }

    public List<FileModel> getAllFilesByPublisher(){
        //Getting uploaded files by current user
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return  fileRepository.findByPublisher(username);
    }
    public List<FileModel> getAllReceiverFiles(){
        //Getting all other uploaded files
        String publisher = SecurityContextHolder.getContext().getAuthentication().getName();
        return  fileRepository.findByPublisherIsNot(publisher);
    }
    public Stream<FileModel> getAllFiles() {
        //Getting all files
        return fileRepository.findAll().stream();
    }
}
