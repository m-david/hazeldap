package com.craftedbytes.hazelcast.security;

import com.hazelcast.nio.ObjectDataInput;
import com.hazelcast.nio.ObjectDataOutput;
import com.hazelcast.nio.serialization.DataSerializable;
import com.hazelcast.security.Credentials;

import java.io.IOException;

public class UserGroupCredentials implements Credentials, DataSerializable {

    private String endpoint;
    private String userGroup;

    public UserGroupCredentials() {
    }

    public UserGroupCredentials(String endPoint, String userGroup) {
        this.endpoint = endPoint;
        this.userGroup = userGroup;
    }

    public String getEndpoint() {
        return this.endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getPrincipal() {
        return this.userGroup;
    }

    public void writeData(ObjectDataOutput objectDataOutput) throws IOException {
        objectDataOutput.writeUTF(endpoint);
        objectDataOutput.writeUTF(userGroup);
    }

    public void readData(ObjectDataInput objectDataInput) throws IOException {
        this.endpoint = objectDataInput.readUTF();
        this.userGroup = objectDataInput.readUTF();
    }

}
