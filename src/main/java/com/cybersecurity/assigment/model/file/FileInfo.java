package com.cybersecurity.assigment.model.file;

public class FileInfo {
    private String name;
    private String type;
    private byte[] data;
    private String url;


    public FileInfo(String name, String type, byte[] data, String url) {
        this.name = name;
        this.type = type;
        this.data = data;
        this.url = url;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
