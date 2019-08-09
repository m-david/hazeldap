package com.craftedbytes.hazelcast.ldap;

import com.craftedbytes.hazelcast.Member;
import com.hazelcast.config.Config;
import com.hazelcast.config.OnJoinPermissionOperationName;
import com.hazelcast.config.XmlConfigBuilder;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.IOException;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class ReceiveConfigTest {

    @BeforeClass
    public static void prepare() {
        Member.start();
    }

    @AfterClass
    public static void teardown() {
        Member.stop();
    }

    @Test
    public void testReceiveConfig() {
        Properties properties = new Properties();

        try {
            properties.load(Member.class.getClassLoader().getResourceAsStream("hazelcast.properties"));
            Config liteConfig = new XmlConfigBuilder(Member.class.getClassLoader().getResourceAsStream("hazelcast-lite.xml"))
                    .setProperties(properties)
                    .build();

            liteConfig.setLiteMember(true);
            liteConfig.getSecurityConfig()
                    .setEnabled(true)
                    .setOnJoinPermissionOperation(OnJoinPermissionOperationName.RECEIVE);

            HazelcastInstance lite = Hazelcast.newHazelcastInstance(liteConfig);

            try {
                assertEquals(2, lite.getConfig().getSecurityConfig().getClientPermissionConfigs().size());
            } finally {
                lite.shutdown();
            }
        }
        catch (IOException e) {
            fail("something happened.");
        }
    }
}
