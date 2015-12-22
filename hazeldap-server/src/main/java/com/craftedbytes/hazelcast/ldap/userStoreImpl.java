package com.craftedbytes.hazelcast.ldap;

import static org.springframework.ldap.query.LdapQueryBuilder.query;

import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import com.craftedbytes.hazelcast.UserStore;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.filter.Filter;
import org.springframework.ldap.filter.WhitespaceWildcardsFilter;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.util.Collections;
import java.util.List;

public class UserStoreImpl implements UserStore {
    private LdapTemplate ldapTemplate;

    public void setLdapTemplate(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public List<String> getAllPersonNames() {

        List<String> search = ldapTemplate
                .search(query().where("objectclass").is("inetOrgPerson"), new AttributesMapper<String>() {
                    public String mapFromAttributes(Attributes attrs)
                            throws NamingException {
                        return attrs.get("cn").get().toString();
                    }
                });


        return search;
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
