package com.craftedbytes.hazelcast.ldap;

import com.craftedbytes.hazelcast.Member;
import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.config.Config;
import com.hazelcast.config.OnJoinPermissionOperationName;
import com.hazelcast.config.PermissionConfig;
import com.hazelcast.config.XmlConfigBuilder;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.security.Credentials;
import com.hazelcast.security.UsernamePasswordCredentials;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.security.AccessControlException;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class AddPermissionTest {

    private static Set<PermissionConfig> immutablePermissions;

    private static String ENDPOINT = "127.0.0.1";

    private static Config getConfig() {
        Properties properties = new Properties();
        Config config = null;
        try {
            properties.load(Member.class.getClassLoader().getResourceAsStream("hazelcast.properties"));

            config = new XmlConfigBuilder(Member.class.getClassLoader().getResourceAsStream("hazelcast-lite.xml"))
                    .setProperties(properties)
                    .build();

            config.setLiteMember(true);
            config.getSecurityConfig()
                    .setEnabled(true)
                    .setOnJoinPermissionOperation(OnJoinPermissionOperationName.RECEIVE);

        }
        catch (IOException e) {
            fail("Unable to initialize: " + e.getLocalizedMessage());
        }

        return config;
    }

    @BeforeClass
    public static void prepare() {

        Member.start();

        Properties properties = new Properties();
        HazelcastInstance lite = null;
        try {
            properties.load(Member.class.getClassLoader().getResourceAsStream("hazelcast.properties"));

            Config config = new XmlConfigBuilder(Member.class.getClassLoader().getResourceAsStream("hazelcast-lite.xml"))
                    .setProperties(properties)
                    .build();

            config.setLiteMember(true);
            config.getSecurityConfig()
                    .setEnabled(true)
                    .setOnJoinPermissionOperation(OnJoinPermissionOperationName.RECEIVE);

            lite = Hazelcast.newHazelcastInstance(config);

            immutablePermissions = lite.getConfig().getSecurityConfig().getClientPermissionConfigs();

        }
        catch (IOException e) {
            fail("Unable to initialize: " + e.getLocalizedMessage());
        }
        finally {
            if(lite != null) {
                lite.shutdown();
            }
        }
    }

    @AfterClass
    public static void teardown() {
        Config config = getConfig();

        config.getSecurityConfig().setOnJoinPermissionOperation(OnJoinPermissionOperationName.SEND);

        config.getSecurityConfig().getClientPermissionConfigs().addAll(immutablePermissions);
        HazelcastInstance lite = null;
        try {
            lite = Hazelcast.newHazelcastInstance(config);
        }
        finally {
            if(lite != null) {
                lite.shutdown();
            }
        }
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
    public void testAddPermission() {

        Config config = getConfig();
        config.getSecurityConfig().setOnJoinPermissionOperation(OnJoinPermissionOperationName.SEND);
        config.getSecurityConfig().getClientPermissionConfigs().addAll(immutablePermissions);

        PermissionConfig mapPermission = new PermissionConfig(PermissionConfig.PermissionType.MAP, "restrictedMap", "StandardUsers");
        mapPermission
                .addAction("create")
                .addAction("read");
        config.getSecurityConfig().getClientPermissionConfigs().add(mapPermission);

        HazelcastInstance lite = Hazelcast.newHazelcastInstance(config);

        ClientConfig clientConfig = getConfig("jbloggs", "password3");
        HazelcastInstance client = HazelcastClient.newHazelcastClient(clientConfig);

        try {
            Map<String, String> restrictedMap = client.getMap("restrictedMap");
            restrictedMap.put("1000", "value-1000");
            fail("Should have failed, 'put' not allowed");
        }
        catch(AccessControlException e) {
            assertNotNull(e);
        }
        finally {
            if(client != null) {
                client.shutdown();
            }
            if(lite != null) {
                lite.shutdown();
            }
        }
    }
}
