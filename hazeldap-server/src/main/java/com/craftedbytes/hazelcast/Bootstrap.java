package com.craftedbytes.hazelcast;

import com.hazelcast.core.HazelcastInstance;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.context.ApplicationContext;

import java.util.List;

public class Bootstrap {

    public static void main(String args[]){

        ApplicationContext applicationContext = new ClassPathXmlApplicationContext("application-context.xml");

        UserStore userStore = applicationContext.getBean("userStore", UserStore.class);

        System.out.println(userStore.authenticate("dbrimley", "password1"));

        System.out.println(userStore.authenticate("dbrimley","badPassword"));

        System.out.println("dbrimley is a member of the following groups ->" + userStore.getRoles("dbrimley"));

        HazelcastInstance hazelcastInstance = (HazelcastInstance) applicationContext.<HazelcastInstance>getBean("hazelcast.instance");

        System.out.println(hazelcastInstance.getConfig());
    }

}
