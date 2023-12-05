package com.cybersecurity.assigment.model.file;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "file")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class FileModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    private String type;

    @Lob
    @Column(name = "file_data", length = 5242880)
    private byte[] data;
    @Lob
    @Column(length = 5242880)
    private byte[] signed;

    @Lob
    @Column(length = 5242880)
    private byte[] encrypted;

    private String publisher; //define the publisher of the file.

    public FileModel(String name, String type, byte[] data, byte[] signed, byte[] encrypted, String publisher) {
        this.name = name;
        this.type = type;
        this.data = data;
        this.signed = signed;
        this.encrypted = encrypted;
        this.publisher = publisher;
    }
}
