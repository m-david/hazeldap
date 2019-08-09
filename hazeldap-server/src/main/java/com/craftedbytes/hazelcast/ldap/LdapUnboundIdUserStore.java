package com.craftedbytes.hazelcast.ldap;

import com.craftedbytes.hazelcast.UserStore;
import com.unboundid.ldap.sdk.*;

import java.util.ArrayList;
import java.util.List;

import static com.craftedbytes.hazelcast.ldap.LdapConstants.ORG_UNIT_PEOPLE;

public class LdapUnboundIdUserStore implements UserStore {

    private LDAPConnectionPool connectionPool;

    private String baseDn;

    public LdapUnboundIdUserStore(String host, int port, String baseDn, String bindDN, String bindPassword, int maxConnections) throws LDAPException {
        this.baseDn = baseDn;
        LDAPConnection connection = new LDAPConnection(host, port, bindDN, bindPassword);
        this.connectionPool = new LDAPConnectionPool(connection, maxConnections);
    }

    @Override
    public boolean authenticate(String username, String password) {

        String bindDn = "uid=" + username + "," + ORG_UNIT_PEOPLE + ", " + baseDn;
        LDAPConnection connection = null;
        boolean success = false;
        try {
            connection = connectionPool.getConnection();
            BindResult result = connection.bind(bindDn, password);
            result.getResultCode().intValue();
            success = connection.isConnected();
        }
        catch (LDAPException e) {
            e.printStackTrace();
        }
        finally {
            if(connection != null) {
                connection.close();
            }
        }
        return success;
    }

    private String getUsernameExpression(String username) {
        StringBuffer expression = new StringBuffer("uid=").append(username).append(", ").append(ORG_UNIT_PEOPLE).append(", ");
        expression.append(baseDn);
        return expression.toString();
    }

    @Override
    public List<String> getRoles(String username) {

        List<String> roles = new ArrayList<String>();
        LDAPConnection connection = null;
        try {
            connection = connectionPool.getConnection();
            Filter filter1 = Filter.createEqualityFilter("objectclass","groupOfUniqueNames");

            Filter filter2 = Filter.createEqualityFilter("uniqueMember", getUsernameExpression(username));
            Filter andFilter = Filter.createANDFilter(filter1, filter2);
            SearchResult result = connection.search(baseDn, SearchScope.SUB, andFilter);

            result.getSearchEntries().forEach(entry ->
            {
                Attribute attribute = entry.getAttribute("cn");
                if(attribute != null) {
                    roles.add(attribute.getValue());
                }
            });
        }
        catch (LDAPException e) {
//            e.printStackTrace();
            return roles;
        }
        finally {
            if(connection != null) {
                connection.close();
            }
        }

        return roles;
    }
}
