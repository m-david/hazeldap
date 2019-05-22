Hazelcast has the ability to authenticate users of a cluster and then to authorise their access to data structures and operations based on roles held by a user.  This authentication and authorisation occurs within the cluster when a client connects for the first time.  

### Introduction to Hazelcast & JAAS

The entire process is handled with the help of [JAAS (Java Authentication and Authorization Service)](https://en.wikipedia.org/wiki/Java_Authentication_and_Authorization_Service) compliant interfaces.

The follow three steps describe at a high level how Hazelcast interacts with JAAS.  The highlighted words denote keywords in the JAAS lexicon.

1. The **Subject**(Hazelcast Client) attempts to connect to a service, in this case a Hazelcast Cluster.  The **Subject** provides **Credentials** when it initially connects.  These **Credentials** can be anything at all, for example a user name and password or maybe a Binary Token.  

2. The **Credentials** are passed to a **LoginModule**, this module is a JAAS interface that is executed by the Hazelcast Cluster when a new client connects.  The implementer of this module may then take the passed **Credentials** and firstly authenticate the user.  The authentication can be carried out against the security service of their choice.  This could just be a Database table of user names and password or it could be a corporate security solution like LDAP or Active Directory.

3. Once the user has been authenticated they can then be authorised to perform actions on data or execute distributed functions.  This authorisation takes the form of matching roles against actions in Hazelcast, for example "Joe Bloggs" has the role of "Admin" therefore he can update all Maps in the cluster.  The roles are generally stored in the same security back-end/database that carried out the Authentication steps, maybe an LDAP or Active Directory store.

The following diagram describes these operations.

![Hazelcast LDAP Security Workflow](/assets/img/hazelcast-ldap-security.png)

### JAAS Login Module Phases

If you examine the diagram above, within the Hazelcast Cluster each member will have a **LoginModule** registered to it (we'll look at how we register the module later on),  The **LoginModule** is an interface defined in the JAAS specification.  It is this interface we need to implement to provide a link between Hazelcast Client connections and our Security back-end.

Now observe the lifecycle phases of the **LoginModule**, in the diagram above we can see *initialise, login & commit*.  There are a couple of others we need to be aware of that handle failed login attempts and also logout.

Here's the JAAS **LoginModule** interface in its entirety.

```java
package javax.security.auth.spi;

import javax.security.auth.Subject;
import javax.security.auth.AuthPermission;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import java.util.Map;

/**
 * <p> <code>LoginModule</code> describes the interface
 * implemented by authentication technology providers.  LoginModules
 * are plugged in under applications to provide a particular type of
 * authentication.
 *
 * <p> While applications write to the <code>LoginContext</code> API,
 * authentication technology providers implement the
 * <code>LoginModule</code> interface.
 * A <code>Configuration</code> specifies the LoginModule(s)
 * to be used with a particular login application.  Therefore different
 * LoginModules can be plugged in under the application without
 * requiring any modifications to the application itself.
 *
 * <p> The <code>LoginContext</code> is responsible for reading the
 * <code>Configuration</code> and instantiating the appropriate
 * LoginModules.  Each <code>LoginModule</code> is initialized with
 * a <code>Subject</code>, a <code>CallbackHandler</code>, shared
 * <code>LoginModule</code> state, and LoginModule-specific options.
 *
 * The <code>Subject</code> represents the
 * <code>Subject</code> currently being authenticated and is updated
 * with relevant Credentials if authentication succeeds.
 * LoginModules use the <code>CallbackHandler</code> to
 * communicate with users.  The <code>CallbackHandler</code> may be
 * used to prompt for usernames and passwords, for example.
 * Note that the <code>CallbackHandler</code> may be null.  LoginModules
 * which absolutely require a <code>CallbackHandler</code> to authenticate
 * the <code>Subject</code> may throw a <code>LoginException</code>.
 * LoginModules optionally use the shared state to share information
 * or data among themselves.
 *
 * <p> The LoginModule-specific options represent the options
 * configured for this <code>LoginModule</code> by an administrator or user
 * in the login <code>Configuration</code>.
 * The options are defined by the <code>LoginModule</code> itself
 * and control the behavior within it.  For example, a
 * <code>LoginModule</code> may define options to support debugging/testing
 * capabilities.  Options are defined using a key-value syntax,
 * such as <i>debug=true</i>.  The <code>LoginModule</code>
 * stores the options as a <code>Map</code> so that the values may
 * be retrieved using the key.  Note that there is no limit to the number
 * of options a <code>LoginModule</code> chooses to define.
 *
 * <p> The calling application sees the authentication process as a single
 * operation.  However, the authentication process within the
 * <code>LoginModule</code> proceeds in two distinct phases.
 * In the first phase, the LoginModule's
 * <code>login</code> method gets invoked by the LoginContext's
 * <code>login</code> method.  The <code>login</code>
 * method for the <code>LoginModule</code> then performs
 * the actual authentication (prompt for and verify a password for example)
 * and saves its authentication status as private state
 * information.  Once finished, the LoginModule's <code>login</code>
 * method either returns <code>true</code> (if it succeeded) or
 * <code>false</code> (if it should be ignored), or throws a
 * <code>LoginException</code> to specify a failure.
 * In the failure case, the <code>LoginModule</code> must not retry the
 * authentication or introduce delays.  The responsibility of such tasks
 * belongs to the application.  If the application attempts to retry
 * the authentication, the LoginModule's <code>login</code> method will be
 * called again.
 *
 * <p> In the second phase, if the LoginContext's overall authentication
 * succeeded (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
 * LoginModules succeeded), then the <code>commit</code>
 * method for the <code>LoginModule</code> gets invoked.
 * The <code>commit</code> method for a <code>LoginModule</code> checks its
 * privately saved state to see if its own authentication succeeded.
 * If the overall <code>LoginContext</code> authentication succeeded
 * and the LoginModule's own authentication succeeded, then the
 * <code>commit</code> method associates the relevant
 * Principals (authenticated identities) and Credentials (authentication data
 * such as cryptographic keys) with the <code>Subject</code>
 * located within the <code>LoginModule</code>.
 *
 * <p> If the LoginContext's overall authentication failed (the relevant
 * REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules did not succeed),
 * then the <code>abort</code> method for each <code>LoginModule</code>
 * gets invoked.  In this case, the <code>LoginModule</code> removes/destroys
 * any authentication state originally saved.
 *
 * <p> Logging out a <code>Subject</code> involves only one phase.
 * The <code>LoginContext</code> invokes the LoginModule's <code>logout</code>
 * method.  The <code>logout</code> method for the <code>LoginModule</code>
 * then performs the logout procedures, such as removing Principals or
 * Credentials from the <code>Subject</code> or logging session information.
 *
 * <p> A <code>LoginModule</code> implementation must have a constructor with
 * no arguments.  This allows classes which load the <code>LoginModule</code>
 * to instantiate it.
 *
 * @see javax.security.auth.login.LoginContext
 * @see javax.security.auth.login.Configuration
 */
public interface LoginModule {

    /**
     * Initialize this LoginModule.
     *
     * <p> This method is called by the <code>LoginContext</code>
     * after this <code>LoginModule</code> has been instantiated.
     * The purpose of this method is to initialize this
     * <code>LoginModule</code> with the relevant information.
     * If this <code>LoginModule</code> does not understand
     * any of the data stored in <code>sharedState</code> or
     * <code>options</code> parameters, they can be ignored.
     *
     * <p>
     *
     * @param subject the <code>Subject</code> to be authenticated. <p>
     *
     * @param callbackHandler a <code>CallbackHandler</code> for communicating
     *                  with the end user (prompting for usernames and
     *                  passwords, for example). <p>
     *
     * @param sharedState state shared with other configured LoginModules. <p>
     *
     * @param options options specified in the login
     *                  <code>Configuration</code> for this particular
     *                  <code>LoginModule</code>.
     */
    void initialize(Subject subject, CallbackHandler callbackHandler,
                    Map<String,?> sharedState,
                    Map<String,?> options);

    /**
     * Method to authenticate a <code>Subject</code> (phase 1).
     *
     * <p> The implementation of this method authenticates
     * a <code>Subject</code>.  For example, it may prompt for
     * <code>Subject</code> information such
     * as a username and password and then attempt to verify the password.
     * This method saves the result of the authentication attempt
     * as private state within the LoginModule.
     *
     * <p>
     *
     * @exception LoginException if the authentication fails
     *
     * @return true if the authentication succeeded, or false if this
     *                  <code>LoginModule</code> should be ignored.
     */
    boolean login() throws LoginException;

    /**
     * Method to commit the authentication process (phase 2).
     *
     * <p> This method is called if the LoginContext's
     * overall authentication succeeded
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
     * succeeded).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * <code>login</code> method), then this method associates relevant
     * Principals and Credentials with the <code>Subject</code> located in the
     * <code>LoginModule</code>.  If this LoginModule's own
     * authentication attempted failed, then this method removes/destroys
     * any state that was originally saved.
     *
     * <p>
     *
     * @exception LoginException if the commit fails
     *
     * @return true if this method succeeded, or false if this
     *                  <code>LoginModule</code> should be ignored.
     */
    boolean commit() throws LoginException;

    /**
     * Method to abort the authentication process (phase 2).
     *
     * <p> This method is called if the LoginContext's
     * overall authentication failed.
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules
     * did not succeed).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * <code>login</code> method), then this method cleans up any state
     * that was originally saved.
     *
     * <p>
     *
     * @exception LoginException if the abort fails
     *
     * @return true if this method succeeded, or false if this
     *                  <code>LoginModule</code> should be ignored.
     */
    boolean abort() throws LoginException;

    /**
     * Method which logs out a <code>Subject</code>.
     *
     * <p>An implementation of this method might remove/destroy a Subject's
     * Principals and Credentials.
     *
     * <p>
     *
     * @exception LoginException if the logout fails
     *
     * @return true if this method succeeded, or false if this
     *                  <code>LoginModule</code> should be ignored.
     */
    boolean logout() throws LoginException;
}
```
## The Example LDAP Secured Hazelcast Cluster

To demonstrate these features I have written a sample Hazelcast Client and a Hazelcast Cluster Member that authenticates and authorizes via an LDAP store.  The rest of this blog post is broken down into 2 sections.

1.  Running the Sample Project.
2.  Implementation Overview.

### Running the Sample Project

The source code for this example can be found at my [github repository](http://github.com/dbrimley/hazeldap)

The example is a maven project that is broken down into two modules.

1. hazeldap-client : This provides a sample client that connects to the cluster and passes a Credentials object on connection.
2. hazeldap-server : This is a Hazelcast cluster member that is configured using Spring Beans.  The member is configured to use a LoginModule that connects to an LDAP store.

#### Step 1 : Hazelcast Enterprise

These features are present in Hazelcast Enterprise, to get started you'll have to grab yourself a trial version from [hazelcast.com](https://hazelcast.com/hazelcast-enterprise-download/trial/).

You'll get two things from the website...

1. A license key.
2. The Hazelcast Enterprise JARS.

##### Configure the License Key

The project samples and hazelcast are bootstrapped using Spring, to configure the license you'll need to edit the following file...

`hazeldap-server/src/main/resources/application-context.properties`

changing the `hazelcast.license.key` value...

```
hazelcast.group.config.name=hazeldap
hazelcast.group.config.password=hazeldap-password
hazelcast.license.key=<!-- GET LICENCE FROM https://hazelcast.com/hazelcast-enterprise-download/trial/ -->
```

##### Add the Enterprise Jars to Maven Repo

Next you'll need to add the enterprise jars you downloaded and place them into your local maven repository.  You can do this using the [maven-install-plugin](https://maven.apache.org/plugins/maven-install-plugin/).  You'll need to do this as the Enterprise version of Hazelcast is not available in the central maven repo on the internet.

For example if you are installing the 3.5.4 jars to your local maven repo you would execute the following on your command line, remembering to change the `-Dfile` and `-DlocalRepositoryPath` values...

```XML
mvn org.apache.maven.plugins:maven-install-plugin:2.5.1:install-file 
-Dfile=path-to/hazelcast-enterprise-client-3.5.4.jar 
-DgroupId=com.hazelcast 
-DartifactId=hazelcast-enterprise-client 
-Dversion=3.5.4 
-Dpackaging=jar 
-DlocalRepositoryPath=path-to/.m2/repository

mvn org.apache.maven.plugins:maven-install-plugin:2.5.1:install-file 
-Dfile=path-to/hazelcast-enterprise-3.5.4.jar 
-DgroupId=com.hazelcast 
-DartifactId=hazelcast-enterprise 
-Dversion=3.5.4 
-Dpackaging=jar 
-DlocalRepositoryPath=path-to/.m2/repository
```

#### Step 2 : Vagrant & OpenLDAP

This example uses a running OpenLDAP server and I've provided a [Vagrant](https://www.vagrantup.com/) script to automatically start an Ubuntu box and using a Chef Script, provision it with OpenLDAP.  The last step in the script executes a command line `ldapadd` command which loads an LDIF file containing the LDAP tree structure of our users and groups, along with the actual user data.

If the paragraph above made no sense, I'd advise you spend some time reading up on Vagrant and Chef.  It's worth the investment, believe me.

To get started with this approach you'll first have to install Vagrant and the Chef Development Kit onto your machine.

1. [Vagrant Getting Started](https://docs.vagrantup.com/v2/getting-started/index.html)
2. [Chef DK](https://downloads.chef.io/chef-dk/)

##### Starting the Vagrant OpenLDAP server

If you have everything installed correctly you'll just need to cd to `hazeldap-server/src/main/vagrant` and then on a command line run

`vagrant up`

If all has gone to plan the last few lines of output to the terminal should be something like this...

```
==> default: adding new entry "dc=craftedbytes,dc=com"
==> default: 
==> default: adding new entry "ou=people,dc=craftedbytes,dc=com"
==> default: 
==> default: adding new entry "ou=groups,dc=craftedbytes,dc=com"
==> default: 
==> default: adding new entry "cn=Administrators,ou=groups,dc=craftedbytes,dc=com"
==> default: 
==> default: adding new entry "cn=SuperUsers,ou=groups,dc=craftedbytes,dc=com"
==> default: 
==> default: adding new entry "cn=StandardUsers,ou=groups,dc=craftedbytes,dc=com"
==> default: 
==> default: adding new entry "uid=dbrimley, ou=people, dc=craftedbytes, dc=com"
==> default: 
==> default: adding new entry "uid=fdibnah, ou=people, dc=craftedbytes, dc=com"
==> default: 
==> default: adding new entry "uid=jbloggs, ou=people, dc=craftedbytes, dc=com"
```

This is telling us that the Ubuntu box is up and the Chef scripts have successfully loaded our LDAP user data.

You can even `ssh` to the Ubuntu Virtual Machine by typing `vagrant ssh`

##### The LDAP User and Roles Data.

This example isn't intended as a guide to LDAP and how data is structured within it, if you are a novice in this area you should examine some of the many tutorials available.

Lets take a look a little more closely at the LDIF file that contains the User and Roles data, `hazeldap-server/src/main/vagrant/ldif/usergroups.ldif`, we've created 3 users and assigned them to 3 groups.


| Group          | User             |
|----------------|------------------|
| Administrators | dbrimley, fdibnah |
| SuperUsers     | dbrimley         |
| StandardUsers  | jbloggs          |


You'll notice in the LDIF file below that each user also has a hashed password, for example `dbrimley` password is `password1`.  You can create an SHA hash by the command line `slappasswd -h {SHA} -s password1`.  You'll need OpenLDAP installed to achieve this.

```
dn: dc=craftedbytes,dc=com
objectclass: dcObject
objectclass: organization
o: craftedbytes.com
dc: craftedbytes

dn: ou=people,dc=craftedbytes,dc=com
objectClass: organizationalUnit
objectClass: top
ou: people

dn: ou=groups,dc=craftedbytes,dc=com
objectClass: organizationalUnit
objectClass: top
ou: groups

dn: cn=Administrators,ou=groups,dc=craftedbytes,dc=com
objectClass: groupofuniquenames
objectClass: top
ou: groups
cn: Administrators
uniquemember: uid=dbrimley, ou=people, dc=craftedbytes,dc=com
uniquemember: uid=fdibnah, ou=people, dc=craftedbytes,dc=com

dn: cn=SuperUsers,ou=groups,dc=craftedbytes,dc=com
objectClass: groupofuniquenames
objectClass: top
ou: groups
cn: SuperUsers
uniquemember: uid=dbrimley, ou=people, dc=craftedbytes,dc=com

dn: cn=StandardUsers,ou=groups,dc=craftedbytes,dc=com
objectClass: groupofuniquenames
objectClass: top
ou: groups
cn: StandardUsers
uniquemember: uid=jbloggs, ou=people, dc=craftedbytes,dc=com

dn: uid=dbrimley, ou=people, dc=craftedbytes, dc=com
objectClass: person
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: top
uid: dbrimley
# password is password1 generated using command line slappasswd -h {SHA} -s password1
userPassword: {SHA}44rSFJQ9qtHWTBAvrsKd5K/p2j0=
cn: David Brimley
sn: David
ou: people

dn: uid=fdibnah, ou=people, dc=craftedbytes, dc=com
objectClass: person
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: top
uid: fdibnah
# password is password2 generated using command line slappasswd -h {SHA} -s password2
userPassword: {SHA}KqYKj/f81HPTIeAUav2eJt85UUc=
cn: Fred Dibnah
sn: Fred
ou: people

dn: uid=jbloggs, ou=people, dc=craftedbytes, dc=com
objectClass: person
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: top
uid: jbloggs
# password is password3 generated using command line slappasswd -h {SHA} -s password3
userPassword: {SHA}ERnP037iRzV+A0oI2ETuol9v0g8=
cn: Joe Bloggs
sn: Joe
ou: people
```



##### Running your own LDAP Server

If you do not wish to use the Vagrant approach you can run your own LDAP server and use the LDIF file found at **src/main/vagrant/ldif/usergroups.ldif**.  The LDIF file describes the LDAP tree and the data found within it.

If you do set-up your own server you'll also have to edit the connection details for where the Hazelcast Cluster Member looks for its LDAP server.  These are at **hazeldap/hazeldap-server/src/main/resources/application-context.properties**

I would recommend using [OpenLDAP](http://www.openldap.org/)

###### Using Docker

If you don't have an LDAP Server or unable to run OpenLDAP above, you can always spin a docker image up as follows ...

```
$cd ./hazeldap-server/src/main/vagrant/ldif/
$docker run -p 389:389 -p 636:636 --name my-openldap-container \
  --env LDAP_ADMIN_PASSWORD="password" \
   --env LDAP_DOMAIN="craftedbytes.com" \
  --detach osixia/openldap:1.2.4

$ldapadd -h localhost -p 389 -x -D cn=admin,dc=craftedbytes,dc=com -w password -f usergroups.ldif
```

Bind Dn:  cn=admin,dc=craftedbytes,dc=com

##### Apache Directory Studio
* Login with bind dn credentials above
* Import ldif:  ./ldif/usergroups.ldif


### Client Credentials

When a Client initially connects to a Hazelcast Cluster an optional [Credentials](http://docs.hazelcast.org/docs/latest/javadoc/com/hazelcast/security/Credentials.html) object can be passed.  The Credentials object carries mandatory information such as the Endpoint which is usually the IP Address of the client.  As Credentials are usually passed over the network between a client and a cluster it needs to be serialized.

You can implement Credentials interface directly and then add extra information you wish to pass like a token or use one of the existing classes, such as [UsernamePasswordCredentials](http://docs.hazelcast.org/docs/latest/javadoc/com/hazelcast/security/UsernamePasswordCredentials.html).  We'll use this class for Credentials in our example project, it has the added advantage of implementing [Portable Serialization](http://docs.hazelcast.org/docs/latest/manual/html-single/index.html#portable).  

UsernamePasswordCredentials takes a String Username and a String Password.

**Make sure you use [SSL on client to cluster connections](http://docs.hazelcast.org/docs/latest/manual/html-single/index.html#ssl) when you are sending clear text passwords over the wire.**

####com.hazelcast.security.Credentials
```java
package com.hazelcast.security;
import java.io.Serializable;
public interface Credentials extends Serializable {
    String getEndpoint();
    void setEndpoint(String var1);
    String getPrincipal();
}
```

Now we have our Credentials object we need to pass it on with our initial Client connection into the Hazelcast cluster, the follow code samples demonstrates this...


####Sending Credentials on Client Connection
```java
ClientConfig clientConfig = new ClientConfig();
clientConfig.setCredentials(new UsernamePasswordCredentials(username, password));
clientConfig.getCredentials().setEndpoint(thisClientIP);
HazelcastInstance hazelcastInstance = HazelcastClient.newHazelcastClient(clientConfig);
```

##Server Side JAAS Login Module

It's time to introduce our implementation of the [LoginModule](http://docs.oracle.com/javase/7/docs/technotes/guides/security/jaas/JAASLMDevGuide.html) Interface and configure the Hazelcast Cluster to use it when a client connects. Our Implementation is called [ClientLoginModule](https://github.com/dbrimley/hazeldap/blob/master/hazeldap-server/src/main/java/com/craftedbytes/hazelcast/security/ClientLoginModule.java). You can have multiple LoginModules chained together and you can configure each module to be required to pass or optional.


```xml
<bean id="hazelcast.instance" class="com.hazelcast.core.Hazelcast" factory-method="newHazelcastInstance">
    <constructor-arg>
        <bean class="com.hazelcast.config.Config">
            <!-- Other Config ommited from this example -->
            <property name="securityConfig">
                <bean class="com.hazelcast.config.SecurityConfig">
                    <property name="enabled" value="true"/>
                    <property name="clientLoginModuleConfigs">
                        <list>
                            <bean class="com.hazelcast.config.LoginModuleConfig">
                                <property name="className"
                                              value="com.craftedbytes.hazelcast.security.ClientLoginModule"/>
                                <property name="usage" value="REQUIRED"/>
                                <property name="properties">
                                    <map>
                                        <entry key="userStore" value-ref="userStore"/>
                                    </map>
                                </property>
                            </bean>
                        </list>
                    </property>
                    <!-- Other Config ommited from this example -->
                </bean>
            </property>
        </bean>
    </constructor-arg>
</bean>
```

Lets now look at each of the LoginModule phases

###Initialize

Hazelcast first calls the initialize method when the client connection is detected.  

Hazelcast passes 4 classes.

1. **Subject** : Is the class that will be populated with Principals (e.g. Roles) upon successful login.
2. **CallbackHandler** : Is used to retrieve the Credentials passed by the client.
3. **SharedState** : Is a Map that can be used to pass state between different LoginModules
4. **Options** : Is used in this instances to pass in helper classes tot he LoginModule, in our case we will be passing in the UserStore which in turn connects to our LDAP server.

```java
public void initialize(Subject subject, 
                       CallbackHandler callbackHandler, 
                       Map<String, ?> sharedState, 
                       Map<String, ?> options) {
    this.subject = subject;
    this.callbackHandler = callbackHandler;
    this.userStore = (UserStore) options.get("userStore");
}
```

####UserStore & LDAP

When we initialize the LoginModule we pass it a [UserStore](https://github.com/dbrimley/hazeldap/blob/master/hazeldap-server/src/main/java/com/craftedbytes/hazelcast/UserStore.java) in the options Map class.

The UserStore is an abstraction that provides two services.

1. The Ability to authenticate a user given a username and a password
2. The Ability to return a set of roles for a given username.

```java
package com.craftedbytes.hazelcast;

import java.util.List;

/**
 * A UserStore that can perform authentication and retrieve roles for a user.
 */
public interface UserStore {

    boolean authenticate(String username, String password);

    List<String> getRoles(String username);
}
```

We have an implementation of this [UserStore](https://github.com/dbrimley/hazeldap/blob/master/hazeldap-server/src/main/java/com/craftedbytes/hazelcast/UserStore.java) that  connects to an LDAP Server called [LdapUserStore](https://github.com/dbrimley/hazeldap/blob/master/hazeldap-server/src/main/java/com/craftedbytes/hazelcast/ldap/LdapUserStore.java), this implementation makes use of [Spring Ldap](http://projects.spring.io/spring-ldap/).

###Login

Next Hazelcast will call the `login` method on `LdapUserStore`.

This phase can be broken down into 2 steps.

1.  We get the `Credentials` object that contains the username and password.
2.  We then call `authenticate` on our `UserStore`.

```java
     /**
     * Login is called when this module is executed.
     *
     * @return true if login successful
     * @throws LoginException
     */
    public boolean login() throws LoginException {
        return authenticateUser(getCredentials());
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
```

###Commit

This phase runs when all the LoginModules have passed.

In this phase we obtain the Roles for the authenticated User by again calling the `UserStore`.  We place a `Principal` object for each role onto the `Subject`.

This `Subject` is then used whenever an action/request is made to hazelcast.

```java
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
```

## Hazelcast Permissions

The final piece of our puzzle is to link the roles we've derived from the LDAP server and how they map onto actions in the Hazelcast cluster.

Hazelcast documents this mapping very well, under the subject of [Authorization](http://docs.hazelcast.org/docs/latest/manual/html-single/index.html#authorization).

In our example project we have used Spring configuration to set properties on the `com.hazelcast.config.SecurityConfig`.  But as you'll see from the Hazelcast documentation you can also create this mapping in XML or even using the configuration API, in which case you could read this mapping information from LDAP as well, or maybe a Database.

In this sample below we've cut out the relevant section of the configuration, you'll find the full configuration in the sample project at `hazeldap-server/src/main/resources/application-context.xml`

You can see from the snippet below that we've created two role mappings against the map called `importantMap`.  There is one role, `cn: StandardUsers` that has the ability to perform `create` and `read` commands on the map.

There is than another role, `cn: Administrators` that is able to perform all commands on the map.

```XML
<property name="clientPermissionConfigs">
     <set>
          <bean class="com.hazelcast.config.PermissionConfig">
               <property name="name" value="importantMap"/>
               <property name="type" value="MAP"/>
               <property name="principal" value="cn: StandardUsers"/>
               <property name="actions">
                    <set>
                         <value>create</value>
                         <value>read</value>
                    </set>
               </property>
          </bean>
          <bean class="com.hazelcast.config.PermissionConfig">
               <property name="name" value="importantMap"/>
               <property name="type" value="MAP"/>
               <property name="principal" value="cn: Administrators"/>
               <property name="actions">
                    <set>
                         <value>create</value>
                         <value>destroy</value>
                         <value>put</value>
                         <value>read</value>
                    </set>
               </property>
          </bean>
     </set>
</property>

```
