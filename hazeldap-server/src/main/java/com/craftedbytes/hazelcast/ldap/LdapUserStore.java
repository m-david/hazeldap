package com.craftedbytes.hazelcast.ldap;

import com.craftedbytes.hazelcast.UserStore;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import java.util.List;

/**
 * A UserStore that connects to an LDAP server by use of the Spring LdapTemplate
 */
public class LdapUserStore implements UserStore {

    private LdapTemplate ldapTemplate;

    public void setLdapTemplate(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public boolean authenticate(String username, String password) {

        Filter filter = new EqualsFilter("uid", username);

        boolean authOk = ldapTemplate.authenticate("OU=people",
                filter.encode(),
                password);

        return authOk;

    }

    public List<String> getRoles(String username) {

        AndFilter filter=new AndFilter();
        filter.and(new EqualsFilter("objectclass","groupOfUniqueNames"));
        filter.and(new EqualsFilter("uniqueMember","uid="+username+", ou=people, dc=craftedbytes, dc=com"));

        List<String> search = ldapTemplate
                .search("", filter.encode(), new AttributesMapper<String>() {
                    public String mapFromAttributes(Attributes attributes) throws NamingException {
                        return attributes.get("cn").toString();
                    }
                });


        return search;
    }
}
