package com.cybersecurity.assigment.repository;

import com.cybersecurity.assigment.model.file.FileModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FileRepository extends JpaRepository<FileModel, Long> {
    List<FileModel> findByPublisher(String username);
}
