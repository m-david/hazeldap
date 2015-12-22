package com.craftedbytes.hazelcast;

import java.util.List;

/**
 * A UserStore that can perform authentication and retrieve roles for a user.
 */
public interface UserStore {

    boolean authenticate(String username, String password);

    List<String> getRoles(String username);
}
