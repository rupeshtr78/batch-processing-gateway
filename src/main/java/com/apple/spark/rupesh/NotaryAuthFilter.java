package com.apple.spark.rupesh;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import static com.apple.spark.core.Constants.LDAP_ENDPOINT;

public class NotaryAuthFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(NotaryAuthFilter.class);
    private final String LDAP_USER_BASE = "cn=users,dc=apple,dc=com";

    private final String LDAP_GROUP_BASE = "cn=groups,dc=apple,dc=com";


    public boolean isGroupMember(final String username, final String groupId) {
        if (username == null || groupId == null) {
            return false;
        }

        final Properties properties = new Properties();
        properties.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        properties.put(Context.PROVIDER_URL, LDAP_ENDPOINT);
        properties.put(Context.SECURITY_PRINCIPAL, "");
        properties.put(Context.SECURITY_CREDENTIALS, "");

        try {
            final LdapContext ldapContext = new InitialLdapContext(properties, null);

            final Attributes matchAttrs = new BasicAttributes(true);
            matchAttrs.put(new BasicAttribute("memberuid", username));
            matchAttrs.put(new BasicAttribute("gidNumber", groupId));

            final NamingEnumeration<SearchResult> namingEnumeration = ldapContext.search(LDAP_GROUP_BASE, matchAttrs);
            if (namingEnumeration.hasMoreElements()) {
                // The return value is ignored. We depend on the thrown exception to indicate failure.
                namingEnumeration.nextElement();
                return true;
            }
        } catch (final NamingException e) {
            LOGGER.warn("Exception from ldap. exception={}", e.getMessage());
            return false;
        }
        return false;
    }


    public void getGroupMembers(final String username, final String groupId) {
        if (username == null || groupId == null) {
            LOGGER.info("No username");
        }

        final Properties properties = new Properties();
        properties.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        properties.put(Context.PROVIDER_URL, LDAP_ENDPOINT);
        properties.put(Context.SECURITY_PRINCIPAL, "");
        properties.put(Context.SECURITY_CREDENTIALS, "");

        try {
            final LdapContext ldapContext = new InitialLdapContext(properties, null);

            final Attributes matchAttrs = new BasicAttributes(true);
            matchAttrs.put(new BasicAttribute("memberuid", username));
            matchAttrs.put(new BasicAttribute("gidNumber", groupId));

            final NamingEnumeration<SearchResult> namingEnumeration = ldapContext.search(LDAP_GROUP_BASE, matchAttrs);

            while (namingEnumeration != null && namingEnumeration.hasMore()) {
                SearchResult sr = namingEnumeration.next();
                String groupResults = String.valueOf(sr.getAttributes().getAll());
                System.out.println(groupResults);
            }

        } catch (final NamingException e) {
            LOGGER.warn("Exception from ldap. exception={}", e.getMessage());
               }


    }

    public static void main(String[] args) {

        NotaryAuthFilter notaryAuthFilter = new NotaryAuthFilter();
        Boolean isUser = notaryAuthFilter.isGroupMember("rupesh_raghavan", "44444");

        notaryAuthFilter.getGroupMembers("rupesh_raghavan", "444444");
        System.out.println(isUser);
    }

}
