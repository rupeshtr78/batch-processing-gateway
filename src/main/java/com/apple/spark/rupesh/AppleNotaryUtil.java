package com.apple.spark.appleinternal;


import com.apple.spark.operator.*;
import com.apple.turi.notary.client.NotaryClient;
import com.apple.turi.notary.client.exception.NotaryException;
import com.apple.turi.notary.openapi.invoker.ApiException;
import com.apple.turi.notary.openapi.model.ApiIssueTokenBody;
import com.apple.turi.notary.openapi.model.ApiIssueTokenResp;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;

public class AppleNotaryUtil {

    private static final Logger logger = LoggerFactory.getLogger(AppleNotaryUtil.class);
    private static final String BPG_NOTARY_APP_PASSWORD = "NOTARY_APPLICATION_PASSWORD";
    private static final String BPG_NOTARY_TOKEN = "NOTARY_ACTOR_TOKEN";
    public static final String BPG_NOTARY_APP_ID = "NOTARY_APPLICATION_ID";
    public static final String BPG_NOTARY_APP_NAMESPACE = "NOTARY_APPLICATION_NAMESPACE";


    public static void enableNotaryEnvironmentVariable(
            SparkApplication sparkApplication,
            @NotNull SparkApplicationSpec sparkSpec) throws GeneralSecurityException, NotaryException, IOException {


        String notary_token = generateNotaryActorToken(sparkApplication);

        EnvVar notaryTokenEnvVar =
                new EnvVar(BPG_NOTARY_TOKEN, notary_token);

        if (sparkSpec.getDriver().getEnv() != null) {
            sparkSpec.getDriver().getEnv().add(notaryTokenEnvVar);
        } else {
            List<EnvVar> tmpListEnvVar = new ArrayList<>();
            tmpListEnvVar.add(notaryTokenEnvVar);
            sparkSpec.getDriver().setEnv(tmpListEnvVar);
        }

        if (sparkSpec.getExecutor().getEnv() != null) {
            sparkSpec.getExecutor().getEnv().add(notaryTokenEnvVar);
        } else {
            List<EnvVar> tmpListEnvVar = new ArrayList<>();
            tmpListEnvVar.add(notaryTokenEnvVar);
            sparkSpec.getExecutor().setEnv(tmpListEnvVar);
        }


    }

    /*
      * application token requires Notary application ID and password,
      * The returned token will be a Notary application identity token.
     */
    private static String generateNotaryApplicationToken() throws GeneralSecurityException, NotaryException, IOException {

        String notaryAppToken;

        String applicationId = getBpgNotaryEnvVars(BPG_NOTARY_APP_ID);
        String applicationPassword = getBpgNotaryEnvVars(BPG_NOTARY_APP_PASSWORD);

        NotaryClient client = NotaryClient.defaultNotaryClient();

        //get an actor authority token first
        try {
            ApiIssueTokenResp appTokenResponse = client.getApplicationToken(applicationId, applicationPassword, new ApiIssueTokenBody());
            notaryAppToken = appTokenResponse.getToken();
        } catch (ApiException e) {
            throw new RuntimeException(e);
        }

        return notaryAppToken;
    }

   /*
    * actor identity: Represents an actor, an actor can be a process, a container or a k8s pod or similar.
    * It’s an entity that can run code on behalf of a person in a trusted cluster/environment.
    * use the actor authority token to get an actor token identity_aprn for actor required as input
    */
    private static String generateNotaryActorToken(@NotNull SparkApplication sparkApplicationResource) throws GeneralSecurityException, NotaryException, IOException {

        String notaryAppToken = generateNotaryApplicationToken();
        String notaryActorToken = null;

        NotaryClient client = NotaryClient.defaultNotaryClient();

        // use the actor authority token to get an actor token identity_aprn for actor required as input
        try {
            String sparkApplicationID = sparkApplicationResource.getMetadata().getName();
            String notaryNameSpace = getBpgNotaryEnvVars(BPG_NOTARY_APP_NAMESPACE);
            String sparkJobIdentityAprn = String.format("aprn:apple:turi::%s:task:%s", notaryNameSpace, sparkApplicationID);

            ApiIssueTokenBody actorBody = new ApiIssueTokenBody();
            actorBody.setIdentityAprn(sparkJobIdentityAprn);

            ApiIssueTokenResp response = client.getActorToken(notaryAppToken, actorBody);
            notaryActorToken = response.getToken();
        } catch (ApiException e) {
            throw new RuntimeException("Failed to Generate Notary Actor Token token", e);
        }


        return notaryActorToken;
    }


    /**
     * Notary token needs to generated only for bpg applications registered with notary.
     * BPG applications will be deployed with notary application id and password env vars
     */

    public static boolean isNotaryApplication(String envVarName) {
        String applicationId = getBpgNotaryEnvVars(envVarName);

        boolean checkNotaryApplication;

        if (applicationId == null || applicationId.isEmpty()) {
            checkNotaryApplication = false;
            logger.info(String.format("Not a notary application Notary env variable %s not found", envVarName));
        } else {
            checkNotaryApplication = true;
            logger.info(String.format("Notary application app id env variable found: %s", applicationId));
        }

        return checkNotaryApplication;
    }

    private static String getBpgNotaryEnvVars(String envVarName) {

        String envValue = System.getenv(envVarName);
        if (envValue == null || envValue.isEmpty()) {
            logger.warn(String.format("Did not find valid env variable: %s", envVarName));
        }

        return envValue;
    }





}
