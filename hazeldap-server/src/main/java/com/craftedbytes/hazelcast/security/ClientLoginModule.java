package com.craftedbytes.hazelcast.security;

import com.craftedbytes.hazelcast.UserStore;
import com.craftedbytes.hazelcast.ldap.LdapUnboundIdUserStore;
import com.hazelcast.logging.ILogger;
import com.hazelcast.logging.Logger;
import com.hazelcast.security.*;
import com.unboundid.ldap.sdk.LDAPException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;

/**
 * An example JAAS LoginModule that makes use of a UserStore to authenticate and then provide groups.
 */
public class ClientLoginModule implements LoginModule {

    private final ILogger logger = Logger.getLogger(getClass().getName());

    private UsernamePasswordCredentials usernamePasswordCredentials;
    private Subject subject;
    private CallbackHandler callbackHandler;

    private UserStore userStore;

    public void initialize(Subject subject,
                           CallbackHandler callbackHandler,
                           Map<String, ?> sharedState,
                           Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        initializeFromOptions(options);
    }

    private void initializeFromOptions(Map<String, ?> options) {
        ConnectionProperties connectionProperties = new ConnectionProperties((Map<String, String>)options);


        try {
            this.userStore = new LdapUnboundIdUserStore(
                    connectionProperties.getHost(),
                    connectionProperties.getPort(),
                    connectionProperties.getBaseDn(),
                    connectionProperties.getBindDn(),
                    connectionProperties.getBindPassword(),
                    connectionProperties.getMaxConnections());
        }
        catch (LDAPException e) {
            e.printStackTrace();
        }

    }

    public void setUserStore(UserStore userStore)
    {
        this.userStore = userStore;
    }

    public UserStore getUserStore()
    {
        return userStore;
    }

    /**
     * Login is called when this module is executed.
     *
     * @return true if login successful
     * @throws LoginException
     */
    public boolean login() throws LoginException {
        return authenticateUser(getCredentials());
    }

    /**
     * Commit is called when all of the modules in the chain have passed.
     *
     * @return true if commit passed successfully
     * @throws LoginException
     */
    public final boolean commit() throws LoginException {
        logger.log(Level.FINEST, "Committing authentication of " + SecurityUtil.getCredentialsFullName(usernamePasswordCredentials));
        storeRolesOnPrincipal();
        return true;
    }

    /**
     * Abort is called when one of the modules in the chain has failed.
     *
     * @return
     * @throws LoginException
     */
    public final boolean abort() throws LoginException {
        logger.log(Level.FINEST, "Aborting authentication of " + SecurityUtil.getCredentialsFullName(usernamePasswordCredentials));
        clearSubject();
        return true;
    }

    /**
     * Graceful Logout
     *
     * @return
     * @throws LoginException
     */
    public final boolean logout() throws LoginException {
        logger.log(Level.FINEST, "Logging out " + SecurityUtil.getCredentialsFullName(usernamePasswordCredentials));
        clearSubject();
        return true;
    }

    private UsernamePasswordCredentials getCredentials() throws LoginException {
        final CredentialsCallback cb = new CredentialsCallback();
        Credentials credentials;
        try {
            callbackHandler.handle(new Callback[]{cb});
            credentials = cb.getCredentials();
        } catch (Exception e) {
            throw new LoginException(e.getClass().getName() + ":" + e.getMessage());
        }

        if (credentials == null) {
            logger.log(Level.WARNING, "Credentials could not be retrieved!");
            throw new LoginException("Credentials could not be retrieved!");
        }

        logger.log(Level.INFO, "Authenticating " + SecurityUtil.getCredentialsFullName(credentials));

        if (credentials instanceof UsernamePasswordCredentials) {
            usernamePasswordCredentials = (UsernamePasswordCredentials) credentials;
            return usernamePasswordCredentials;
        } else {
            throw new LoginException("Credentials not type of UsernamePasswordCredentials");
        }
    }

    private boolean authenticateUser(UsernamePasswordCredentials credentials) {
        String username = credentials.getUsername();
        String password = credentials.getPassword();
        return userStore.authenticate(username, password);
    }

    private void storeRolesOnPrincipal() throws LoginException {
        List<String> userGroups = userStore.getRoles(usernamePasswordCredentials.getUsername());
        if (userGroups != null) {
            for (String userGroup : userGroups) {
                Principal principal = new ClusterPrincipal(new UserGroupCredentials(usernamePasswordCredentials.getEndpoint(), userGroup));
                subject.getPrincipals().add(principal);
            }
        } else {
            logger.log(Level.WARNING, "User Group(s) not found for user " + usernamePasswordCredentials.getUsername());
            throw new LoginException("User Group(s) not found for user " + usernamePasswordCredentials.getUsername());
        }
    }

    /**
     * Tidy up the Subject
     */
    private void clearSubject() {
        subject.getPrincipals().clear();
        subject.getPrivateCredentials().clear();
        subject.getPublicCredentials().clear();
    }

}
