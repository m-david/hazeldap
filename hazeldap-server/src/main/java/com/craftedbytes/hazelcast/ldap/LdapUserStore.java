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

import static com.craftedbytes.hazelcast.ldap.LdapConstants.ORG_UNIT_PEOPLE;

/**
 * A UserStore that connects to an LDAP server by use of the Spring LdapTemplate
 */

public class LdapUserStore implements UserStore {

    private LdapTemplate ldapTemplate;

    private String baseDn;



    public void setLdapTemplate(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    public void setBaseDn(String baseDn) {
        this.baseDn = baseDn;
    }

    public boolean authenticate(String username, String password) {

        Filter filter = new EqualsFilter("uid", username);

        boolean authOk = ldapTemplate.authenticate(ORG_UNIT_PEOPLE
                ,
                filter.encode(),
                password);

        return authOk;

    }

    private String getUsernameExpression(String username) {
        StringBuffer expression = new StringBuffer("uid=").append(username).append(", ").append(ORG_UNIT_PEOPLE).append(", ");
        expression.append(baseDn);
        return expression.toString();
    }

    public List<String> getRoles(String username) {

        AndFilter filter=new AndFilter();
        filter.and(new EqualsFilter("objectclass","groupOfUniqueNames"));
        filter.and(new EqualsFilter("uniqueMember", getUsernameExpression(username)));

        List<String> roles = ldapTemplate
                .search("", filter.encode(), new AttributesMapper<String>() {
                    public String mapFromAttributes(Attributes attributes) throws NamingException {
                        return attributes.get("cn").toString();
                    }
                });

        return roles;
    }
}
