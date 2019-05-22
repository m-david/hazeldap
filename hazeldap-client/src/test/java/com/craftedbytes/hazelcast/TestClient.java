package com.craftedbytes.hazelcast;

import com.hazelcast.core.HazelcastInstance;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.AccessControlException;
import java.util.Map;
import java.util.logging.Level;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class TestClient
{

    private static Client client;

    @BeforeClass
    public static void init()
    {
        client = new Client();
    }

    @Test
    public void testReadOnlyuserCanOnlyReadNotWrite()
    {
        HazelcastInstance readOnlyClient = client.getClientConnection("jbloggs", "password3", "127.0.0.1");

        Map<String, String> readOnlyClientsImportantMap = readOnlyClient.getMap("importantMap");

        assertNotNull(readOnlyClientsImportantMap.get("1"), "-------------> Joe is performing get on the ImportantMap (Should've Passed)");

        try
        {
            readOnlyClientsImportantMap.put("2", "2");
            fail("-------------> Joe is performing put on the ImportantMap (Should Fail)");
        } catch (AccessControlException e)
        {
            //, "Could not perform put operation, access denied"
            assertNotNull(e);
        }

    }

    @Test
    public void testAdminUserCanReadAndWrite() {

        HazelcastInstance adminClient = client.getClientConnection("dbrimley", "password1", "127.0.0.1");

        Map<String,String> adminClientsImportantMap = adminClient.getMap("importantMap");

        // This will pass
//        logger.log(Level.INFO,"-------------> David is performing put on the ImportantMap (Should Pass)");
        assertNotNull(adminClientsImportantMap.get("1"), "-------------> David is performing get on the ImportantMap (Should've Passed)");
        assertNotNull(adminClientsImportantMap.put("1","1"), "-------------> David is performing put on the ImportantMap (Should've Passed)");

    }

}
