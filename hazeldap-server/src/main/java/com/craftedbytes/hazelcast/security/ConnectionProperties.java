package com.craftedbytes.hazelcast.security;

import java.util.Map;

import static com.craftedbytes.hazelcast.ldap.LdapConstants.MAX_CONNECTIONS;

public class ConnectionProperties {

    private String host;
    private int port;
    private String baseDn;
    private String bindDn;
    private String bindPassword;
    private int maxConnections;


    public ConnectionProperties(Map<String, String> options) {
        this.host = options.get("host");
        String portStr = options.get("port");
        this.port = portStr == null ? 0 : Integer.valueOf(portStr);
        this.bindPassword = options.get("bindPassword");
        this.baseDn = options.get("baseDn");
        this.bindDn = options.get("bindDn");
        String maxString = options.get("maxConnections");
        this.maxConnections = maxString == null ? MAX_CONNECTIONS : Integer.valueOf(maxString);
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getBindPassword() {
        return bindPassword;
    }

    public int getMaxConnections() {
        return maxConnections;
    }

    public String getBaseDn() {
        return baseDn;
    }

    public String getBindDn() {
        return bindDn;
    }
}
