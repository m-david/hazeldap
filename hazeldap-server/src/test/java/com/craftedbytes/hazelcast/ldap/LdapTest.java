package com.craftedbytes.hazelcast.ldap;

import com.craftedbytes.hazelcast.Member;
import com.unboundid.ldap.sdk.*;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.ldap.core.AttributesMapper;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import static com.craftedbytes.hazelcast.ldap.LdapConstants.MAX_CONNECTIONS;
import static org.junit.Assert.*;

public class LdapTest {

    static LdapUnboundIdUserStore userStore = null;

    @BeforeClass
    public static void init() throws LDAPException {

        Member.start();

        String host = "localhost";
        int port = 389;
        String baseDn = "dc=craftedbytes,dc=com";
        String bindDn = "cn=admin,dc=craftedbytes,dc=com";
        String bindPassword ="password";
        int maxConnections = MAX_CONNECTIONS;

        userStore = new LdapUnboundIdUserStore(host, port, baseDn, bindDn, bindPassword, maxConnections);
    }

    @AfterClass
    public static void cleanup() {
        userStore = null;
        Member.stop();
    }

    @Test
    public void testAuthenticateTrue() throws LDAPException {
        String username = "dbrimley";
        String password = "password1";
        assertTrue(userStore.authenticate(username, password));
    }

    @Test
    public void testAuthenticateFalse() throws LDAPException {
        String username = "invalid_user";
        String password = "password1";
        assertFalse(userStore.authenticate(username, password));
    }


    @Test
    public void testRole() throws LDAPException {

        String username = "dbrimley";
        List<String> roles = userStore.getRoles(username);
        assertEquals(2, roles.size());
    }

    @Test
    public void testNoRoles() throws LDAPException {

        String username = "d_invalid_user";
        List<String> roles = userStore.getRoles(username);

        assertEquals(0, roles.size());
    }

    @Test
    public void testConnections() {
        String username = "dbrimley";

        IntStream.range(0, MAX_CONNECTIONS*2).parallel().forEach(iterCount -> {
            List<String> roles = userStore.getRoles(username);
            assertEquals(2, roles.size());
        });
    }
}
