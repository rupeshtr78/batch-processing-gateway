package com.apple.spark.rupesh;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class NotaryValidateRequestBody {

    //      actorAprn: required, aprn of the actor identity
    public String actorAprn;

    //      assumeAprn: aprn of the assume identity
    public String assumeAprn;
    //      audience: required, list of audience aprn requested
    public List<String> audience;
    //      sourceIp: IP address of the original assume request
    public List<String> sourceIp;
    //      claims: optional, list of custom claims requested
    public Map<String, String> claims;

    public String getActorAprn() {
        return actorAprn;
    }

    public void setActorAprn(String actorAprn) {
        this.actorAprn = actorAprn;
    }

    public String getAssumeAprn() {
        return assumeAprn;
    }

    public void setAssumeAprn(String assumeAprn) {
        this.assumeAprn = assumeAprn;
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public List<String> getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(List<String> sourceIp) {
        this.sourceIp = sourceIp;
    }

    public Map<String, String> getClaims() {
        return claims;
    }

    public void setClaims(Map<String, String> claims) {
        this.claims = claims;
    }


}
