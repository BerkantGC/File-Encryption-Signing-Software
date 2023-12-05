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

@Service
public class FilesStorageService{
    private final Path root = Paths.get("uploads");

    @Autowired
    private FileRepository fileRepository;

    public FileModel save(MultipartFile file) throws IOException{
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        FileModel fileModel = new FileModel(
                fileName,
                file.getContentType(),
                file.getBytes(),
                null, null,
                SecurityContextHolder.getContext().getAuthentication().getName());

        return fileRepository.save(fileModel);
    }

    public FileModel getFile(Integer id)
    {
        return fileRepository.findById(id.longValue()).get();
    }

    public Stream<FileModel> getAllFiles() {
        return fileRepository.findAll().stream();
    }
}
