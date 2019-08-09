package com.craftedbytes.hazelcast;

import com.hazelcast.config.Config;
import com.hazelcast.config.XmlConfigBuilder;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

public class Member {

    private static HazelcastInstance member1;
    private static HazelcastInstance member2;

    public static void start() {

        Properties properties = new Properties();
        try {
            properties.load(Member.class.getClassLoader().getResourceAsStream("hazelcast.properties"));

            Config config = new XmlConfigBuilder(Member.class.getClassLoader().getResourceAsStream("hazelcast.xml"))
                    .setProperties(properties)
                    .build();

            member1 = Hazelcast.newHazelcastInstance(config);
            member2 = Hazelcast.newHazelcastInstance(config);
        }
        catch(FileNotFoundException e) {
            e.printStackTrace();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void stop() {

        if(member1 != null) {
            member1.shutdown();
        }
        if(member2 != null) {
            member2.shutdown();
        }
    }

}
