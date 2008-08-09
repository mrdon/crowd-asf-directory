package org.twdata.asfproxy;

import com.atlassian.crowd.integration.directory.RemoteDirectory;
import com.atlassian.crowd.integration.model.RemotePrincipal;
import com.atlassian.crowd.integration.model.RemoteGroup;
import com.atlassian.crowd.integration.model.RemoteRole;
import com.atlassian.crowd.integration.exception.*;
import com.atlassian.crowd.integration.authentication.PasswordCredential;
import com.atlassian.crowd.integration.SearchContext;

import java.util.Map;
import java.util.List;
import java.util.HashMap;
import java.util.Date;
import java.rmi.RemoteException;
import java.io.IOException;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.methods.GetMethod;

/**
 *
 */
public class ASFRemoteDirectory implements RemoteDirectory {
    public long getID() {
        return 0;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public void setID(long ID) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public String getDirectoryType() {
        return "ASF Proxy Directory";
    }

    public Map getAttributes() {
        return new HashMap();
    }

    public void setAttributes(Map attributes) {
    }

    public RemotePrincipal addPrincipal(RemotePrincipal principal) throws InvalidPrincipalException, RemoteException, InvalidCredentialException {
        throw new UnsupportedOperationException();
    }

    public RemoteGroup addGroup(RemoteGroup group) throws InvalidGroupException, RemoteException {
        throw new UnsupportedOperationException();
    }

    public RemotePrincipal authenticate(String name, PasswordCredential[] credentials) throws RemoteException, InvalidPrincipalException, InactiveAccountException, InvalidAuthenticationException {
        HttpClient client = new HttpClient();

        // pass our credentials to HttpClient, they will only be used for
        // authenticating to servers with realm "realm" on the host
        // "www.verisign.com", to authenticate against
        // an arbitrary realm or host change the appropriate argument to null.
        client.getState().setCredentials(null, "svn.apache.org",
            new UsernamePasswordCredentials(name, credentials[0].getCredential())
        );
        client.getState().setAuthenticationPreemptive(true);

        // create a GET method that reads a file over HTTPS, we're assuming
        // that this file requires basic authentication using the realm above.
        GetMethod get = new GetMethod("https://svn.apache.org/repos/private/");

        // Tell the GET method to automatically handle authentication. The
        // method will use any appropriate credentials to handle basic
        // authentication requests.  Setting this value to false will cause
        // any request for authentication to return with a status of 401.
        // It will then be up to the client to handle the authentication.
        try {
            // execute the GET
            int status = 0;
            try {
                System.out.println(get.getRequestHeaders());
                status = client.executeMethod( get );
                if (status == 401) {
                    System.out.println("Unauthorized");
                    return null;
                } else {
                    RemotePrincipal principal = new RemotePrincipal(name);
                    principal.setAttribute(RemotePrincipal.FIRSTNAME, "");
                    principal.setAttribute(RemotePrincipal.LASTNAME, name);
                    principal.setAttribute(RemotePrincipal.PASSWORD_LASTCHANGED, Long.toString(new Date().getTime()));
                    principal.setAttribute(RemotePrincipal.REQUIRES_PASSSWORD_CHANGE, Boolean.FALSE.toString());
                    principal.setAttribute(RemotePrincipal.EMAIL, name+"@apache.org");
                    principal.setAttribute(RemotePrincipal.DISPLAYNAME, name);
                    return principal;
                }
            } catch (IOException e) {
                throw new RemoteException("Unable to authenticate", e);
            }
        } finally {
            // release any connection resources used by the method
            get.releaseConnection();
        }
    }

    public boolean isGroupMember(String group, String principal) throws RemoteException {
        return false;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public List searchGroups(SearchContext searchContext) throws RemoteException {
        throw new UnsupportedOperationException();
    }

    public RemoteGroup findGroupByName(String name) throws RemoteException, ObjectNotFoundException {
       throw new UnsupportedOperationException();
    }

    public RemoteGroup updateGroup(RemoteGroup group) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public List searchRoles(SearchContext searchContext) throws RemoteException {
        throw new UnsupportedOperationException();
    }

    public RemoteRole findRoleByName(String name) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public RemoteRole addRole(RemoteRole role) throws InvalidRoleException, RemoteException {
        throw new UnsupportedOperationException();
    }

    public RemoteRole updateRole(RemoteRole role) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public void removeGroup(String name) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public void removeRole(String name) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public List searchPrincipals(SearchContext searchContext) throws RemoteException {
        throw new UnsupportedOperationException();
    }

    public RemotePrincipal findPrincipalByName(String name) throws RemoteException, ObjectNotFoundException {
        RemotePrincipal principal = new RemotePrincipal(name);
        principal.setAttribute(RemotePrincipal.FIRSTNAME, "");
        principal.setAttribute(RemotePrincipal.LASTNAME, name);
        principal.setAttribute(RemotePrincipal.PASSWORD_LASTCHANGED, Long.toString(new Date().getTime()));
        principal.setAttribute(RemotePrincipal.REQUIRES_PASSSWORD_CHANGE, Boolean.FALSE.toString());
        principal.setAttribute(RemotePrincipal.EMAIL, name+"@apache.org");
        principal.setAttribute(RemotePrincipal.DISPLAYNAME, name);
        return principal;
    }

    public RemotePrincipal updatePrincipal(RemotePrincipal principal) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public void addPrincipalToGroup(String name, String unsubscribedGroup) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public void removePrincipalFromGroup(String name, String unsubscribedGroup) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public void addPrincipalToRole(String name, String unsubscribedRole) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public void removePrincipalFromRole(String name, String removeRole) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public void removePrincipal(String name) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public void updatePrincipalCredential(String name, PasswordCredential credential) throws RemoteException, ObjectNotFoundException, InvalidCredentialException {
        throw new UnsupportedOperationException();
    }

    public void testConnection() throws RemoteException {
        HttpClient client = new HttpClient();

        // create a GET method that reads a file over HTTPS, we're assuming
        // that this file requires basic authentication using the realm above.
        GetMethod get = new GetMethod("https://svn.apache.org/repos/private/");

        // Tell the GET method to automatically handle authentication. The
        // method will use any appropriate credentials to handle basic
        // authentication requests.  Setting this value to false will cause
        // any request for authentication to return with a status of 401.
        // It will then be up to the client to handle the authentication.
        try {
            // execute the GET
            int status = 0;
            try {
                client.executeMethod( get );
            } catch (IOException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
        } finally {
            // release any connection resources used by the method
            get.releaseConnection();
        }
    }

    public boolean isRoleMember(String role, String principal) throws RemoteException {
        return true;
    }

    public List findGroupMemberships(String principal) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }

    public List findRoleMemberships(String principalName) throws RemoteException, ObjectNotFoundException {
        throw new UnsupportedOperationException();
    }
}
