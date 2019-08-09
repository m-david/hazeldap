package com.craftedbytes.hazelcast.ldap;

import com.craftedbytes.hazelcast.Member;
import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.security.Credentials;
import com.hazelcast.security.UsernamePasswordCredentials;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.AccessControlException;
import java.util.Map;

import static org.junit.Assert.*;

public class ClientTest {

    private static String ENDPOINT = "127.0.0.1";

    @BeforeClass
    public static void prepare() {
        Member.start();
    }

    @AfterClass
    public static void teardown() {
        Member.stop();
    }

    private ClientConfig getConfig(String username, String password) {

        Credentials credentials = new UsernamePasswordCredentials(username, password);

        ClientConfig clientConfig = new ClientConfig();
        clientConfig.getGroupConfig().setName("my-server");
        clientConfig.getNetworkConfig().addAddress("127.0.0.1:5501");

        clientConfig.getSecurityConfig().setCredentials(credentials);
        clientConfig.getSecurityConfig().getCredentials().setEndpoint(ENDPOINT);
        return  clientConfig;

    }

    @Test
    public void testBadLogin() {

        ClientConfig clientConfig = getConfig("jbloggs", "bad_password");
        HazelcastInstance client = null;

        try {
            client = HazelcastClient.newHazelcastClient(clientConfig);
            fail("Should not have made it here.");
        }
        catch (IllegalStateException e) {
            assertNotNull(e);
        }

    }

    @Test
    public void testGoodLogin() {

        ClientConfig clientConfig = getConfig("dbrimley", "password1");
        HazelcastInstance client = null;

        try {
            client = HazelcastClient.newHazelcastClient(clientConfig);
        }
        catch (IllegalStateException e) {
            fail("Should be able to log in");
        }

    }

    @Test
    public void testWriteDenied() {
        ClientConfig clientConfig = getConfig("jbloggs", "password3");
        HazelcastInstance client = HazelcastClient.newHazelcastClient(clientConfig);
        Map<String, String> importantMap = client.getMap("importantMap");

        try {
            importantMap.put("2", "value-2");
            fail("Should not be able to write.");
        }
        catch (AccessControlException e) {
            e.printStackTrace();
            assertTrue(true);

        }
        finally {
            client.shutdown();
        }
    }

    @Test
    public void testWriteApproved() {
        ClientConfig clientConfig = getConfig("dbrimley", "password1");
        HazelcastInstance client = HazelcastClient.newHazelcastClient(clientConfig);

        try {

            Map<String, String> importantMap = client.getMap("importantMap");

            importantMap.put("2", "value-2");
        }
        catch (AccessControlException e) {
            e.printStackTrace();
            assertNotNull(e);

        }
        finally {
            client.shutdown();
        }
    }
}
