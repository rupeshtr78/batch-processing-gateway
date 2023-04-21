package com.apple.spark.api;

import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NotaryValidateResponse {

    public Boolean assumable;

    public List<String> audience;

    public Map<String,String> claims;

    public Boolean getAssumable() {
        return assumable;
    }

    public void setAssumable(Boolean assumable) {
        this.assumable = assumable;
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public Map<String, String> getClaims() {
        return claims;
    }

    public void setClaims(Map<String, String> claims) {
        this.claims = claims;
    }




}
