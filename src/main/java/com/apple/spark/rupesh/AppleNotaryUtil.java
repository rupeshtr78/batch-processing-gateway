package com.apple.spark.appleinternal;


import com.apple.spark.operator.*;
import com.apple.turi.notary.client.NotaryClient;
import com.apple.turi.notary.openapi.model.ApiIssueTokenBody;
import com.apple.turi.notary.openapi.model.ApiIssueTokenResp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class AppleNotaryUtil {

    private static final Logger logger = LoggerFactory.getLogger(AppleNotaryUtil.class);
    private static final String BPG_NOTARY_APP_PASSWORD = "NOTARY_APPLICATION_PASSWORD";
    private static final String BPG_NOTARY_TOKEN = "NOTARY_ACTOR_TOKEN";
    public static final String BPG_NOTARY_APP_ID = "NOTARY_APPLICATION_ID";
    public static final String BPG_NOTARY_APP_NAMESPACE = "NOTARY_APPLICATION_NAMESPACE";


    public static void enableNotaryEnvironmentVariable(
            SparkApplication sparkApplication,
            SparkApplicationSpec sparkSpec) {


        String notary_token = generateNotaryToken(sparkApplication);

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

    public static String generateNotaryToken(SparkApplication sparkApplicationResource) {

        String notaryActorToken = null;

        try {
            String applicationId = getBpgNotaryEnvVars(BPG_NOTARY_APP_ID);
            String applicationPassword = getBpgNotaryEnvVars(BPG_NOTARY_APP_PASSWORD);

            NotaryClient client = NotaryClient.defaultNotaryClient();

//          get an actor authority token first
            ApiIssueTokenResp appTokenResponse = client.getApplicationToken(applicationId, applicationPassword, new ApiIssueTokenBody());
            String notaryAppToken = appTokenResponse.getToken();

//          use the actor authority token to get an actor token identity_aprn for actor required as input
            String sparkApplicationID = sparkApplicationResource.getMetadata().getName();
            String sparkJobIdentityAprn = String.format("aprn:apple:turi::bpg-siri-aws-test:task:%s", sparkApplicationID);

            ApiIssueTokenBody actorBody = new ApiIssueTokenBody();
            actorBody.setIdentityAprn(sparkJobIdentityAprn);
            ApiIssueTokenResp response = client.getActorToken(notaryAppToken, actorBody);
            notaryActorToken = response.getToken();


        } catch (Exception ex) {
            logger.warn("Failed to Generate Notary Token token incorrect Application id or password", ex);
        }

        return notaryActorToken;
    }




    public static boolean checkNotaryApplication(String envVarName) {
        String applicationId = getBpgNotaryEnvVars(envVarName);

        boolean isNotaryApplication = true;

        if (applicationId.isEmpty()) {
            logger.warn("Not a notary application application app id env variable not found");
            isNotaryApplication = false;
        } else {
            logger.info(String.format("Notary application app id env variable found: %s", applicationId));

        }

        return isNotaryApplication;
    }

    public static String getBpgNotaryEnvVars(String envVarName) {

        String envValue = System.getenv(envVarName);
        if (envValue == null || envValue.isEmpty()) {
            throw new RuntimeException(String.format("Did not find valid env variable: %s", envVarName));
        }

        return envValue;
    }





}
