package com.apple.spark.appleinternal;

import com.apple.spark.AppConfig;
import com.apple.spark.api.NotaryValidateResponse;
import com.apple.spark.core.LogDao;
import com.apple.spark.rest.RestBase;
import com.codahale.metrics.annotation.Timed;
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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;


//   @TODO Add separate POD instance for notary validation check like hidden MONITOR_APPLICATION_SYSTEM_PROPERTY_NAME APP_MONITOR_ENABLED
//   @TODO Add rateLimiterListSubmissions
//   @TODO validate endpoint get user from LogDao.
//   @TODO add other response statuses
//   @TODO memory cache to avoid hitting mysql database too heavily
//   200 (OK): Request was processed successfully and response is provided
//   400 (Malformed Request): Request arguments are invalid or lack required fields
//   401 (Unauthorized access): Identity of request is not valid

import static com.apple.spark.core.Constants.LDAP_ENDPOINT;
import static com.apple.spark.core.SparkConstants.RUNNING_STATE;
import static com.apple.spark.core.SparkConstants.SUBMITTED_STATE;


@Path("/actor-assumablity-check")
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
    @Timed
    public NotaryValidateResponse validateNotaryIdentity(NotaryValidateRequestBody validateRequestBody) {

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

        Boolean validUserIdentity = checkUserIdentity(actorAprn, assumeAprn);

        if (validUserIdentity) {
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

    private Boolean checkUserIdentity(String actorAprn, String assumeAprn ) {
        String submissionId = getIdentityFromAprn(actorAprn);
        String actorAssumePersonId = getIdentityFromAprn(assumeAprn);
        Boolean isValidIdentity = false;

        String sparkJobUser;
        try {
            sparkJobUser = getUserFromDb(submissionId);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        logger.debug("Spark job Username from skatedb: " + sparkJobUser);

        String sparkUserDsid = getDsidFromAcUserName(sparkJobUser);
        logger.debug("Dsid of Username from skatedb: " + sparkUserDsid);

        if (Objects.equals(sparkUserDsid, actorAssumePersonId)) {
            isValidIdentity = true;
        } else {
            logger.info(String.format("Spark job User %s does not match Notary Identity %s", sparkUserDsid, actorAssumePersonId));
        }

        return isValidIdentity;
    }

    private String getIdentityFromAprn(String notaryIdentityAprn){

            String output = "";
            try {
                if (notaryIdentityAprn.isEmpty() || notaryIdentityAprn.isBlank()) {
                    logger.error("Error Empty aprn string");
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
            user = logDao.getUserStatusFromSubmissionId(submissionId);
        } catch (Exception e) {
            logger.warn(
                    String.format("Could not get user for submission_id: %s from database", submissionId), e);
        }
        return user;
    }


    private String getUserFromDb(String submissionId) throws SQLException {
        String user = null;

        String sql =
                String.format(
                        "SELECT user, status from %s.application_submission where submission_id = ?", submissionId);

        ResultSet queryResult = logDao.dbQuery(sql);
        String status = queryResult.getString("status");

        if (status.equals(RUNNING_STATE) || status.equals(SUBMITTED_STATE)) {
            user = queryResult.getString("user");
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







