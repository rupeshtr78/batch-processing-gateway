package com.apple.spark.rest;

import com.apple.spark.AppConfig;
import com.apple.spark.api.NotaryValidateResponse;
import com.apple.spark.appleinternal.NotaryValidateRequestBody;
import com.apple.spark.core.LogDao;
import com.apple.turi.notary.client.exception.NotaryException;
import com.apple.turi.notary.openapi.invoker.ApiException;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.*;


//   @TODO Add separate POD instance for notary validation check like hidden MONITOR_APPLICATION_SYSTEM_PROPERTY_NAME APP_MONITOR_ENABLED
//   @TODO Add rateLimiterListSubmissions
//   @TODO validate endpoint get user from LogDao.
//   @TODO add other response status

import static com.apple.spark.core.Constants.LDAP_ENDPOINT;


@Path( "/notary" )
@Consumes({MediaType.APPLICATION_JSON, "text/yaml", MediaType.WILDCARD})
@Produces(MediaType.APPLICATION_JSON)
public class NotaryRest extends RestBase {

    private static final Logger logger = LoggerFactory.getLogger(NotaryRest.class);
    private final LogDao logDao;

    public NotaryRest(AppConfig appConfig, MeterRegistry meterRegistry) {
        super(appConfig, meterRegistry);

        String dbConnectionString = null;
        String dbUser = null;
        String dbPassword = null;
        String dbName = null;

        if (appConfig.getDbStorageSOPS() != null) {
            dbConnectionString = appConfig.getDbStorageSOPS().getConnectionString();
            dbUser = appConfig.getDbStorageSOPS().getUser();
            dbPassword = appConfig.getDbStorageSOPS().getPasswordDecodedValue();
            dbName = appConfig.getDbStorageSOPS().getDbName();
        }

        this.logDao = new LogDao(dbConnectionString, dbUser, dbPassword, dbName, meterRegistry);
    }


    @POST
    @Path("/actor-assumablity-check")
    public NotaryValidateResponse validateNotaryIdentity(NotaryValidateRequestBody validateRequestBody)
            throws GeneralSecurityException, NotaryException, IOException, ApiException {

//IDMS we regiaster notary app
//        "actorAprn": "aprn:apple:turi::bpg-siri-aws-test:task:c0502-a82a388c13d74b668a3122bf4975b5db",
//        "assumeAprn": "aprn:apple:turi::notary:person:2700862372",
//        "audience": ["aprn:apple:turi::notary:application-group:turi-platform","aprn:apple:turi::notary:application-group:polymer"],
//        "sourceIp": ["172.19.198.80"],
//        "claims": {}

        NotaryValidateResponse response = new NotaryValidateResponse();

        List<String> audience = validateRequestBody.getAudience();
        String actorAprn = validateRequestBody.getActorAprn();
        String assumeAprn = validateRequestBody.getAssumeAprn();
        Map<String,String> claims = validateRequestBody.getClaims();
        List<String> sourceIp = validateRequestBody.getSourceIp();

        if (actorAprn == null || (assumeAprn == null)  ) {
                throw new WebApplicationException(
                        "Invalid notary validate request missing Assume Aprn or Actor Aprn",
                        Response.Status.BAD_REQUEST);
        }


        String submissionId = getIdentityFromAprn(actorAprn);
        String actorAssumePersonId = getIdentityFromAprn(assumeAprn);

        String sparkJobUsername = getUserFromSubmissionIdFromDB(submissionId);
        logger.debug("Spark job Username from skatedb: " + sparkJobUsername);

        String assumeIdentiyDsid = getDsidFromAcUserName(sparkJobUsername);
        logger.debug("Dsid of Username from skatedb: " + assumeIdentiyDsid);


        if (Objects.equals(assumeIdentiyDsid, actorAssumePersonId)) {
            response.setAssumable(Boolean.TRUE);
            response.setAudience(List.of("aprn:apple:turi::notary:application-group:turi-platform"));
            response.setClaims(claims);

        } else {
            response.setAssumable(Boolean.FALSE);
            response.setAudience(List.of("aprn:apple:turi::notary:application-group:turi-platform"));
            response.setClaims(claims);
        }


       return response;


    }

    private String getIdentityFromAprn(String notaryIdentityAprn){

            String output = "";
            try {
                if (notaryIdentityAprn.isEmpty() || notaryIdentityAprn.isBlank()) {
                    logger.error("Error while parsing empty aprn string");
                  } else {
                    int aprnIndex = notaryIdentityAprn.lastIndexOf(':') + 1;
                    output =  notaryIdentityAprn.substring(aprnIndex);
                    logger.debug("Extracted identity from aprn: " + output);
                }
            } catch (Exception e) {
                logger.error("Error while parsing the aprn: " + e);
            }
            return output;
        }



    private String getUserFromSubmissionIdFromDB(String submissionId) {
        String user = "";
        try {
            user = logDao.getUserFromSubmissionId(submissionId);
        } catch (Exception e) {
            logger.warn(
                    String.format("Could not get user for submission_id: %s from database", submissionId), e);
        }
        return user;
    }

    /**
     * Query Ldap and get the DSID of a AppleConnect userName. This method is needed since airflow
     * currently uses the airflow bot to authenticate. This should be removed after re-design of
     * Airflow to Skate authentication.
     *
     * @param acUserName
     * @return
     */
    private static String getDsidFromAcUserName(String acUserName) {
        String dsid = "";
        try {
            final Properties properties = new Properties();
            properties.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            properties.put(Context.PROVIDER_URL, LDAP_ENDPOINT);
            properties.put(Context.SECURITY_PRINCIPAL, "");
            properties.put(Context.SECURITY_CREDENTIALS, "");

            LdapContext ctx = new InitialLdapContext(properties, null);
            ctx.setRequestControls(null);

            NamingEnumeration<?> namingEnum =
                    ctx.search("cn=users,dc=apple,dc=com", "uid=" + acUserName, getSimpleSearchControls());

            while (namingEnum.hasMore()) {
                SearchResult result = (SearchResult) namingEnum.next();
                Attributes attrs = result.getAttributes();
                dsid = attrs.get("uidNumber").get().toString();
            }
            namingEnum.close();
        } catch (Exception e) {
            logger.warn("Failed to query DSID by Ldap search for user {}", acUserName, e);
        }
        return dsid;
    }


    private static SearchControls getSimpleSearchControls() {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setTimeLimit(30000);
        return searchControls;
    }


}



