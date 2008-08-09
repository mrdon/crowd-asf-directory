package org.twdata.asfproxy;

import junit.framework.TestCase;
import com.atlassian.crowd.integration.exception.InvalidAuthenticationException;
import com.atlassian.crowd.integration.exception.InvalidPrincipalException;
import com.atlassian.crowd.integration.exception.InactiveAccountException;
import com.atlassian.crowd.integration.model.RemotePrincipal;
import com.atlassian.crowd.integration.authentication.PasswordCredential;

import java.rmi.RemoteException;

/**
 *
 */
public class ASFRemoteDirectoryTest extends TestCase {

    public void testCall() throws InvalidAuthenticationException, InvalidPrincipalException, InactiveAccountException, RemoteException {
        ASFRemoteDirectory dir = new ASFRemoteDirectory();
        dir.authenticate("bob", new PasswordCredential[]{new PasswordCredential("jim")});
    }
}
