package com.sravan.customgranttypehandler;


import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.PasswordGrantHandler;


import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.core.util.MultivaluedMapImpl;

public class Handler extends PasswordGrantHandler {

	

	public Handler() {
		super();
	}

	@Override
	public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) {
		OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
		tokReqMsgCtx.setAuthorizedUser(oAuth2AccessTokenReqDTO.getResourceOwnerUsername());
		tokReqMsgCtx.setScope(oAuth2AccessTokenReqDTO.getScope());
		return this.doAuthorization(tokReqMsgCtx);
	}

	public boolean doAuthorization(OAuthTokenReqMessageContext tokReqMsgCtx) {
		
		return this.authorizeUsingSDP(tokReqMsgCtx);
	}

	public boolean authorizeUsingSDP(OAuthTokenReqMessageContext tokReqMsgCtx) {

		System.out.println("Using sravan for authorization");

		OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
		String username = oAuth2AccessTokenReqDTO.getResourceOwnerUsername();
		String password = oAuth2AccessTokenReqDTO.getResourceOwnerPassword();
		MultivaluedMapImpl formData = new MultivaluedMapImpl();
		formData.add("username", username);
		formData.add("password", password);
		formData.add("tenantDomain", oAuth2AccessTokenReqDTO.getTenantDomain());

		Client restClient = Client.create();
		WebResource webResource = restClient.resource("http://localhost:8080/Spring4MVCCRUDRestService/authenticate/");
		ClientResponse resp = webResource.type("application/x-www-form-urlencoded")
				.post(ClientResponse.class, formData);

		if (resp.getStatus() != 200) {
			System.out.println("Unable to connect to the server due to response status : " + resp.getStatus());
			return false;
		} else {
			String output = resp.getEntity(String.class);

			if (resp.getStatus() != 200) {
				System.out.println("Unable to connect to the server due to response status : " + resp.getStatus());
				return false;
			} else {
				System.out.println("Message from custom:" + output);
				return output.contains("true");
			}
		}

	}
}
