package com.craftedbytes.hazelcast;

import java.util.List;

/**
 * Created by dbrimley on 26/01/15.
 */
public interface UserStore {

    List<String> getAllPersonNames();

    boolean authenticate(String username, String password);

    List<String> getRoles(String username);
}
