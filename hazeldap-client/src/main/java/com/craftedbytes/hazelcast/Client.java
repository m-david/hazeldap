package com.craftedbytes.hazelcast;

import com.hazelcast.client.HazelcastClient;
import com.hazelcast.client.config.ClientClasspathXmlConfig;
import com.hazelcast.client.config.ClientConfig;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.logging.ILogger;
import com.hazelcast.logging.Logger;
import com.hazelcast.security.UsernamePasswordCredentials;

import java.security.AccessControlException;
import java.util.Map;
import java.util.logging.Level;

public class Client {

    private final ILogger logger = Logger.getLogger(getClass().getName());

    public static void main(String args[]){

        Client client = new Client();

        client.adminUserCanPutIntoImportantMap();

        client.readOnlyUserCannotPutIntoImportantMap();

    }

    private void readOnlyUserCannotPutIntoImportantMap() {

        HazelcastInstance readOnlyClient = getClientConnection("jbloggs", "password3", "127.0.0.1");

        Map<String,String> readOnlyClientsImportantMap = readOnlyClient.getMap("importantMap");

        // This will pass
        logger.log(Level.INFO,"-------------> Joe is performing get on the ImportantMap (Should Pass)");
        readOnlyClientsImportantMap.get("1");

        // This will fail as Joe is not a member of the correct group.
        try{
            logger.log(Level.INFO,"-------------> Joe is performing put on the ImportantMap (Should Fail)");
            readOnlyClientsImportantMap.put("2","2");
        } catch (AccessControlException e){
            logger.log(Level.SEVERE,"Could not perform put operation, access denied",e);
        }
    }

    private void adminUserCanPutIntoImportantMap() {

        HazelcastInstance adminClient = getClientConnection("dbrimley", "password1", "127.0.0.1");

        Map<String,String> adminClientsImportantMap = adminClient.getMap("importantMap");

        // This will pass
        logger.log(Level.INFO,"-------------> David is performing put on the ImportantMap (Should Pass)");
        adminClientsImportantMap.put("1","1");
    }

    public HazelcastInstance getClientConnection(String username, String password, String thisClientIP) {
        ClientConfig clientConfig = new ClientClasspathXmlConfig("hazelcast-client.xml");
        clientConfig.setCredentials(new UsernamePasswordCredentials(username, password));
        clientConfig.getCredentials().setEndpoint(thisClientIP);
        return HazelcastClient.newHazelcastClient(clientConfig);
    }
}
