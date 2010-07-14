package controllers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URLDecoder;
import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import models.GoogleAuthProcess;
import org.expressme.openid.Association;
import org.expressme.openid.Authentication;
import org.expressme.openid.Base64;
import org.expressme.openid.Endpoint;
import org.expressme.openid.OpenIdManager;
import play.Play;
import play.cache.Cache;
import play.mvc.*;
import play.data.validation.*;
import play.libs.*;
import play.utils.*;

public class Secure extends Controller {

    public static final String GOOGLEURL = "https://www.google.com/accounts/o8/site-xrds?hd=";

    @Before(unless = {"login", "authenticate", "logout", "askdomain", "finishAuth"})
    static void checkAccess() throws Throwable {
        // Authent
        if (!session.contains("username")) {
            flash.put("url", "GET".equals(request.method) ? request.url : "/"); // seems a good default
            login();
        }
        // Checks
        Check check = getActionAnnotation(Check.class);
        if (check != null) {
            check(check);
        }
        check = getControllerInheritedAnnotation(Check.class);
        if (check != null) {
            check(check);
        }
    }

    private static void check(Check check) throws Throwable {
        for (String profile : check.value()) {
            boolean hasProfile = (Boolean) Security.invoke("check", profile);
            if (!hasProfile) {
                Security.invoke("onCheckFailed", profile);
            }
        }
    }

    // ~~~ Login
    public static void login() throws Throwable {
        Http.Cookie remember = request.cookies.get("rememberme");
        if (remember != null && remember.value.indexOf("-") > 0) {
            String sign = remember.value.substring(0, remember.value.indexOf("-"));
            String username = remember.value.substring(remember.value.indexOf("-") + 1);
            if (Crypto.sign(username).equals(sign)) {
                session.put("username", username);
                redirectToOriginalURL();
            }
        }

        flash.keep("url");
        // If user set the withgoogle to true, we just need to redirect.
        if (Play.configuration.getProperty("auth.withgoogle", "false").equals("true")) {
            String domain = Play.configuration.getProperty("auth.googledomain", request.domain);
//            System.out.println(domain);

            askGoogle(domain);
            return;

        }
        render();
    }

    static void askGoogle(String domain) {
        OpenIdManager manager = new OpenIdManager();

        Long id = GoogleAuthProcess.nextID();
        String finishID = "auth" + id.toString();

        manager.setRealm("http://" + request.domain + "/");
        Map map = new HashMap();
        map.put("id", finishID);
        manager.setReturnTo("http://" + request.domain + Router.reverse("Secure.finishAuth",map));


        Endpoint endpoint = manager.lookupEndpoint(GOOGLEURL + domain);
        Association association = manager.lookupAssociation(endpoint);
        String authUrl = manager.getAuthenticationUrl(endpoint, association);

        GoogleAuthProcess process = new GoogleAuthProcess();
        process.manager = manager;
        process.association = association;
        process.endPoint = endpoint;

        Cache.add(finishID, process, "10min");

        flash.keep("url");
        System.out.println("Redirecting to : "+authUrl);
        System.out.println("-------------");
        redirect(authUrl);


    }

    public static void finishAuth(String id) {
        System.out.println("Finish authentication");

        try {
            System.out.println("Get process with ID " + id);
            GoogleAuthProcess process = (GoogleAuthProcess) Cache.get(id);
            if (process == null) {
                System.out.println("No process");
                return;
            }
            OpenIdManager manager = process.manager;
            Authentication auth = manager.getAuthentication(createRequest(request.url), process.association.getRawMacKey(), "ext1");

            System.out.println(auth.getFullname());
            session.put("username", auth.getIdentity());
            session.put("fullName", auth.getFullname());
            session.put("firstName", auth.getFirstname());
            session.put("lastName", auth.getLastname());
            session.put("language", auth.getLanguage());
            session.put("email", auth.getEmail());
            redirectToOriginalURL();
        } catch (Throwable ex) {
            Logger.getLogger(Secure.class.getName()).log(Level.SEVERE, null, ex);
        }


    }

    static HttpServletRequest createRequest(String url) throws UnsupportedEncodingException {
        int pos = url.indexOf('?');
        if (pos == (-1)) {
            throw new IllegalArgumentException("Bad url.");
        }
        String query = url.substring(pos + 1);
        String[] urlparams = query.split("[\\&]+");
        final Map<String, String> map = new HashMap<String, String>();
        for (String param : urlparams) {
            pos = param.indexOf('=');
            if (pos == (-1)) {
                throw new IllegalArgumentException("Bad url.");
            }
            String key = param.substring(0, pos);
            String value = param.substring(pos + 1);
            map.put(key, URLDecoder.decode(value, "UTF-8"));
        }
        return (HttpServletRequest) Proxy.newProxyInstance(
                Secure.class.getClassLoader(),
                new Class[]{HttpServletRequest.class},
                new InvocationHandler() {

                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        if (method.getName().equals("getParameter")) {
                            return map.get((String) args[0]);
                        }
                        throw new UnsupportedOperationException(method.getName());
                    }
                });
    }

    public static void authenticate(@Required String username, String password, boolean remember) throws Throwable {
        // Check tokens
        Boolean allowed = false;
        try {
            // This is the deprecated method name
            allowed = (Boolean) Security.invoke("authentify", username, password);
        } catch (UnsupportedOperationException e) {
            // This is the official method name
            allowed = (Boolean) Security.invoke("authenticate", username, password);
        }
        if (Validation.hasErrors() || !allowed) {
            flash.keep("url");
            flash.error("secure.error");
            params.flash();
            login();
        }
        // Mark user as connected
        session.put("username", username);
        // Remember if needed
        if (remember) {
            response.setCookie("rememberme", Crypto.sign(username) + "-" + username, "30d");
        }
        // Redirect to the original URL (or /)
        redirectToOriginalURL();
    }

    public static void logout() throws Throwable {
        session.clear();
        response.setCookie("rememberme", "", 0);
        Security.invoke("onDisconnected");
        flash.success("secure.logout");
        login();
    }

    // ~~~ Utils
    static void redirectToOriginalURL() throws Throwable {
        Security.invoke("onAuthenticated");
        String url = flash.get("url");
        if (url == null) {
            url = "/";
        }
        redirect(url);
    }

    public static class Security extends Controller {

        /**
         * @Deprecated
         *
         * @param username
         * @param password
         * @return
         */
        static boolean authentify(String username, String password) {
            throw new UnsupportedOperationException();
        }

        /**
         * This method is called during the authentication process. This is where you check if
         * the user is allowed to log in into the system. This is the actual authentication process
         * against a third party system (most of the time a DB).
         *
         * @param username
         * @param password
         * @return true if the authentication process succeeded
         */
        static boolean authenticate(String username, String password) {
            return true;
        }

        /**
         * This method checks that a profile is allowed to view this page/method. This method is called prior
         * to the method's controller annotated with the @Check method.
         *
         * @param profile
         * @return true if you are allowed to execute this controller method.
         */
        static boolean check(String profile) {
            return true;
        }

        /**
         * This method returns the current connected username
         * @return
         */
        static String connected() {
            return session.get("username");
        }

        /**
         * Indicate if a user is currently connected
         * @return  true if the user is connected
         */
        static boolean isConnected() {
            return session.contains("username");
        }

        /**
         * This method is called after a successful authentication.
         * You need to override this method if you with to perform specific actions (eg. Record the time the user signed in)
         */
        static void onAuthenticated() {
        }

        /**
         * This method is called after a successful sign off.
         * You need to override this method if you with to perform specific actions (eg. Record the time the user signed off)
         */
        static void onDisconnected() {
        }

        /**
         * This method is called if a check does not succeed. By default it shows the not allowed page (the controller forbidden method).
         * @param profile
         */
        static void onCheckFailed(String profile) {
            forbidden();
        }

        private static Object invoke(String m, Object... args) throws Throwable {
            Class security = null;
            List<Class> classes = Play.classloader.getAssignableClasses(Security.class);
            if (classes.isEmpty()) {
                security = Security.class;
            } else {
                security = classes.get(0);
            }
            try {
                return Java.invokeStaticOrParent(security, m, args);
            } catch (InvocationTargetException e) {
                throw e.getTargetException();
            }
        }
    }
}
