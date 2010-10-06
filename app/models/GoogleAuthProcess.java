package models;

import java.io.Serializable;
import org.expressme.openid.Association;
import org.expressme.openid.Authentication;
import org.expressme.openid.Endpoint;
import org.expressme.openid.OpenIdManager;

/**
 *
 * @author judu
 */
public class GoogleAuthProcess implements Serializable {

    public static final Long serialVersionUID = 1L;

    public static Long authID = 1L;

    public OpenIdManager manager;
    public Endpoint endPoint;
    public Association association;
    public Authentication auth;

    public GoogleAuthProcess() {}

    public static Long nextID () {
        return authID++;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || ! (obj instanceof GoogleAuthProcess))
            return false;
        final GoogleAuthProcess other = (GoogleAuthProcess) obj;
        if (this.manager != other.manager && (this.manager == null || !this.manager.equals(other.manager)))
            return false;
        if (this.endPoint != other.endPoint && (this.endPoint == null || !this.endPoint.equals(other.endPoint)))
            return false;
        if (this.association != other.association && (this.association == null || !this.association.equals(other.association)))
            return false;
        if (this.auth != other.auth && (this.auth == null || !this.auth.equals(other.auth)))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 53 * hash + (this.manager != null ? this.manager.hashCode() : 0);
        hash = 53 * hash + (this.endPoint != null ? this.endPoint.hashCode() : 0);
        hash = 53 * hash + (this.association != null ? this.association.hashCode() : 0);
        hash = 53 * hash + (this.auth != null ? this.auth.hashCode() : 0);
        return hash;
    }
}
