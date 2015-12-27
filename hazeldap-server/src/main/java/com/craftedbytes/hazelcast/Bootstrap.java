package com.craftedbytes.hazelcast;

import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.context.ApplicationContext;

import java.util.List;

public class Bootstrap {

    public static void main(String args[]){

        ApplicationContext applicationContext = new ClassPathXmlApplicationContext("application-context.xml");

        UserStore userStore = applicationContext.getBean("userStore", UserStore.class);

        System.out.println(userStore.authenticate("dbrimley", "password"));

        System.out.println(userStore.authenticate("dbrimley","badPassword"));

        System.out.println("dbrimley is a member of the following groups ->" + userStore.getRoles("dbrimley"));
    }

}
