/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.Arrays;
import org.cloudfoundry.identity.uaa.message.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountSetup;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestOperations;

/**
 * @author Dave Syer
 *
 */
public class PasswordChangeEndpointIntegrationTests {

    private final String JOE = "joe_" + new RandomValueStringGenerator().generate().toLowerCase();
    private final String BOB = "bob_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String userEndpoint = "/Users";

    @Rule
    public ServerRunning serverRunning = ServerRunning.isRunning();

    private UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @Rule
    public TestAccountSetup testAccountSetup = TestAccountSetup.standard(serverRunning, testAccounts);

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.withTestAccounts(serverRunning, testAccounts);

    private RestOperations client;

    private ScimUser joe;
    private ScimUser bob;

    private ResponseEntity<ScimUser> createUser(String username, String firstName, String lastName, String email) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setPassword("password");
        return client.postForEntity(serverRunning.getUrl(userEndpoint), user, ScimUser.class);
    }

    @Before
    public void createRestTemplate() throws Exception {
        // Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));
        client = serverRunning.getRestTemplate();
    }

    @BeforeOAuth2Context
    @OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
    public void createAccount() throws Exception {
        client = serverRunning.getRestTemplate();
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
        joe = response.getBody();
        assertEquals(JOE, joe.getUserName());
        response = createUser(BOB, "Bob", "User", "bob@blah.com");
        bob = response.getBody();
        assertEquals(BOB, bob.getUserName());
    }

    private String implicitUrl() {
        URI uri = serverRunning.buildUri("/oauth/authorize").queryParam("response_type", "token")
                .queryParam("client_id", "vmc").queryParam("redirect_uri", "https://uaa.cloudfoundry.com/redirect/vmc")
                .queryParam("scope", "cloud_controller.read").build();
        return uri.toString();
    }

    // XXX I (aocole) believe this test is incorrect. This allows a client with the password.change scope
    // change any user's password, even without uaa.admin scope. This contradicts docs at:
    // https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-Security.md#password-change
    @Test
    @OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
    public void testChangePasswordSucceeds() throws Exception {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers), null, joe.getId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

    }

    @Test
    @OAuth2ContextConfiguration(resource=OAuth2ContextConfiguration.Implicit.class, initialize=false)
    public void testUserChangesOwnPassword() throws Exception {

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
        parameters.set("source", "credentials");
        parameters.set("username", joe.getUserName());
        parameters.set("password", "password");
        context.getAccessTokenRequest().putAll(parameters);

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers), null, joe.getId());
        assertEquals(HttpStatus.OK, result.getStatusCode());

        // Now try logging in with the new credentials
        headers = new HttpHeaders();
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        String credentials = String.format("{ \"username\":\"%s\", \"password\":\"%s\" }", joe.getUserName(),
                "newpassword");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
        formData.add("credentials", credentials);
        result = serverRunning.postForResponse(implicitUrl(), headers, formData);

        assertNotNull(result.getHeaders().getLocation());
        assertTrue(result.getHeaders().getLocation().toString()
                .matches("https://uaa.cloudfoundry.com/redirect/vmc#access_token=.+"));
    }

    @Test
    @OAuth2ContextConfiguration(resource=OAuth2ContextConfiguration.Implicit.class, initialize=false)
    public void testUserChangesOthersPasswordFails() throws Exception {

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
        parameters.set("source", "credentials");
        parameters.set("username", joe.getUserName());
        parameters.set("password", "password");
        context.getAccessTokenRequest().putAll(parameters);

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers), null, bob.getId());
        assertEquals(HttpStatus.FORBIDDEN, result.getStatusCode());

    }

    @Test
    @OAuth2ContextConfiguration(resource=OAuth2ContextConfiguration.Implicit.class, initialize=false)
    public void testUserMustSupplyOldPassword() throws Exception {

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<String, String>();
        parameters.set("source", "credentials");
        parameters.set("username", joe.getUserName());
        parameters.set("password", "password");
        context.getAccessTokenRequest().putAll(parameters);

        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");

        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Void> result = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}/password",
                HttpMethod.PUT, new HttpEntity<PasswordChangeRequest>(change, headers), null, joe.getId());
        assertEquals(HttpStatus.BAD_REQUEST, result.getStatusCode());

    }

}
