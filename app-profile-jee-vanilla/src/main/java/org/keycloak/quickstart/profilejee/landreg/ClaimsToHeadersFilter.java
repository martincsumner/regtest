package org.keycloak.quickstart.profilejee.landreg;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.*;

import javax.servlet.http.HttpServletRequestWrapper;

import org.keycloak.Token;
import org.keycloak.adapters.*;
import org.keycloak.representations.AccessToken;

@WebFilter("/AuthenticationFilter")
public class ClaimsToHeadersFilter implements Filter {

    private ServletContext context;

    public void init(FilterConfig fConfig) throws ServletException {
        this.context = fConfig.getServletContext();
        this.context.log("AuthenticationFilter initialized");
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        final RefreshableKeycloakSecurityContext keycloakSecurityContext = (RefreshableKeycloakSecurityContext) req.getAttribute("org.keycloak.KeycloakSecurityContext");
        final AccessToken accessToken = keycloakSecurityContext.getToken();

            String name = accessToken.getName();
            String email = accessToken.getEmail();


        HeaderMapRequestWrapper requestWrapper = new HeaderMapRequestWrapper(req);
        String remote_addr = request.getRemoteAddr();
        requestWrapper.addHeader("jwtclaim_name", name);
        requestWrapper.addHeader("jwtclaim_email", email);

        chain.doFilter(requestWrapper, response);
    }

    public void destroy() {
        //close any resources here
    }



    public class HeaderMapRequestWrapper extends HttpServletRequestWrapper {
        /**
         * construct a wrapper for this request
         *
         * @param request
         */
        public HeaderMapRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        private Map<String, String> headerMap = new HashMap<String, String>();

        /**
         * add a header with given name and value
         *
         * @param name
         * @param value
         */
        public void addHeader(String name, String value) {
            headerMap.put(name, value);
        }

        @Override
        public String getHeader(String name) {
            String headerValue = super.getHeader(name);
            if (headerMap.containsKey(name)) {
                headerValue = headerMap.get(name);
            }
            return headerValue;
        }

        /**
         * get the Header names
         */
        @Override
        public Enumeration<String> getHeaderNames() {
            List<String> names = Collections.list(super.getHeaderNames());
            for (String name : headerMap.keySet()) {
                names.add(name);
            }
            return Collections.enumeration(names);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            List<String> values = Collections.list(super.getHeaders(name));
            if (headerMap.containsKey(name)) {
                values.add(headerMap.get(name));
            }
            return Collections.enumeration(values);
        }
    }
}