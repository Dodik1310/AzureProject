// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.msalwebsample;

import java.io.IOException;
import java.net.*;
import java.text.ParseException;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.microsoft.aad.msal4j.*;
import com.nimbusds.jwt.JWTParser;
import com.sun.mail.iap.Response;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class AuthPageController {
    @Autowired
    AuthHelper authHelper;


    @RequestMapping("/msal-web-sample-0.1.0/")
    public String homepage() {
        return "index";
    }

    @RequestMapping("/msal4jsample/secure/aad")
    public ModelAndView securePage(HttpServletRequest httpRequest) throws ParseException {
        ModelAndView mav = new ModelAndView("auth_page");

        setAccountInfo(mav, httpRequest);

        return mav;
    }

    @RequestMapping("/msal4jsample/sign_out")
    public void signOut(HttpServletRequest httpRequest, HttpServletResponse response) throws IOException {

        httpRequest.getSession().invalidate();

        String endSessionEndpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/logout";

        String redirectUrl = "https://localhost:8443/msal-web-sample-0.1.0/msal4jsample";
        response.sendRedirect(endSessionEndpoint + "?post_logout_redirect_uri=" +
                URLEncoder.encode(redirectUrl, "UTF-8"));
    }

    @RequestMapping("/msal4jsample/graph/me")
    public ModelAndView getUserFromGraph(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
            throws Throwable {

        IAuthenticationResult result;
        ModelAndView mav;
        try {
            result = authHelper.getAuthResultBySilentFlow(httpRequest, httpResponse);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof MsalInteractionRequiredException) {
                // If silent call returns MsalInteractionRequired, then redirect to Authorization endpoint
                // so user can consent to new scopes
                String state = UUID.randomUUID().toString();
                String nonce = UUID.randomUUID().toString();

                SessionManagementHelper.storeStateAndNonceInSession(httpRequest.getSession(), state, nonce);
                String authorizationCodeUrl = authHelper.getAuthorizationCodeUrl(
                        httpRequest.getParameter("claims"),
                        "User.Read",
                        authHelper.getRedirectUriGraph(),
                        state,
                        nonce);
                return new ModelAndView("redirect:" + authorizationCodeUrl);
            } else {

                mav = new ModelAndView("error");
                mav.addObject("error", e);
                return mav;
            }
        }

        if (result == null) {
            mav = new ModelAndView("error");
            mav.addObject("error", new Exception("AuthenticationResult not found in session."));
        } else {
            mav = new ModelAndView("auth_page");
            setAccountInfo(mav, httpRequest);

            try {
                mav.addObject("userInfo", getUserInfoFromGraph(result.accessToken()));

                return mav;
            } catch (Exception e) {
                mav = new ModelAndView("error");
                mav.addObject("error", e);
            }
        }
        return mav;
    }

    private String getUserInfoFromGraph(String accessToken) throws Exception {
        // Microsoft Graph user endpoint
        URL url = new URL(authHelper.getMsGraphEndpointHost() + "v1.0/me");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "application/json");
        String response = HttpClientHelper.getResponseStringFromConn(conn);

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException(response);
        }

        JSONObject responseObject = HttpClientHelper.processResponse(responseCode, response);
        JSONObject responseMsg = responseObject.getJSONObject("responseMsg");
        String id = responseObject.getJSONObject("responseMsg").get("id").toString();
        JSONArray userRoles = getUserRole(accessToken, id);
        JSONObject resultJson = new JSONObject();
        resultJson.put("id", id);
        resultJson.put("displayName", responseMsg.get("displayName"));
        resultJson.put("login", responseMsg.get("userPrincipalName"));
        resultJson.put("emailAddress", responseMsg.get("userPrincipalName"));
        resultJson.put("roles", userRoles);
        return resultJson.toString();
    }

    private JSONArray getUserRole(String accessToken, String userId) throws Exception {
        // Microsoft Graph user endpoint
        // Get user appRole
        URL url = new URL(authHelper.getMsGraphEndpointHost() + "v1.0/users/" + userId + "/appRoleAssignments");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Length", "306");
        String response = HttpClientHelper.getResponseStringFromConn(conn);

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException(response);
        }

        JSONObject responseObject = HttpClientHelper.processResponse(responseCode, response);
        JSONObject responseMsg = responseObject.getJSONObject("responseMsg");
        JSONArray jsonArray = responseMsg.getJSONArray("value");
        JSONObject obj = null;
        JSONArray arrayOfRoles = null;
        if (jsonArray != null && jsonArray.length() > 0) {
            obj = jsonArray.getJSONObject(0);
        }
        if (obj != null) {
            arrayOfRoles = getAllApplicationRole(accessToken, obj.getString("resourceId"));
        }
        JSONArray resultJsonArray = new JSONArray();
        if (arrayOfRoles != null) {
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject object = jsonArray.getJSONObject(i);
                for (int j = 0; j < arrayOfRoles.length(); j++) {
                    if (arrayOfRoles.getJSONObject(j).get("id").equals(object.get("appRoleId"))) {
                        resultJsonArray.put(arrayOfRoles.getJSONObject(j).getString("displayName"));
                    }
                }
            }
        }
        return resultJsonArray;
    }

    private JSONArray getAllApplicationRole(String accessToken, String resourceId) throws Exception {
        // Get all role for application
        URL url = new URL(authHelper.getMsGraphEndpointHost() + "v1.0/servicePrincipals/" + resourceId);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        // Set the appropriate header fields in the request header.
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Length", "110");
        String response = HttpClientHelper.getResponseStringFromConn(conn);

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException(response);
        }
        JSONObject responseObject = HttpClientHelper.processResponse(responseCode, response);
        JSONObject responseMsg = responseObject.getJSONObject("responseMsg");
        JSONArray jsonArray = responseMsg.getJSONArray("appRoles");
        return jsonArray;
    }


    private void setAccountInfo(ModelAndView model, HttpServletRequest httpRequest) throws ParseException {
        IAuthenticationResult auth = SessionManagementHelper.getAuthSessionObject(httpRequest);

        String tenantId = JWTParser.parse(auth.idToken()).getJWTClaimsSet().getStringClaim("tid");

        model.addObject("tenantId", tenantId);
        model.addObject("account", SessionManagementHelper.getAuthSessionObject(httpRequest).account());
    }


}



