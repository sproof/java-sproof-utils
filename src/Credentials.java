package at.ac.fhsalzburg.sproof;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Containerklasse fuer Zugangsdaten
 */
public class Credentials {

    private org.web3j.crypto.Credentials credentials;
    private String seed;

    /**
     * erstellt die Zugangsdaten aus dem gegebenen Private Key und speichert zusaetzlich den seed fuer die spaetere
     * Verwendung
     * @param privKey Private Key aus dem die Zugangsdaten erstellt werden sollen
     * @param seed Seed String der fuer das Erstellen des Private Keys verwendet wurde
     */
    public Credentials(BigInteger privKey, String seed) {
        this.credentials = org.web3j.crypto.Credentials.create(privKey.toString(16));
        this.seed = seed;
    }

    public BigInteger getPublicKey() {
        return credentials.getEcKeyPair().getPublicKey();
    }

    public BigInteger getPrivateKey() {
        return credentials.getEcKeyPair().getPrivateKey();
    }

    public String getAddress() {
        return credentials.getAddress();
    }

    public String getSeed() {
        return seed;
    }

    /**
     * liefert das zugrundeliegende Credentials Objekt zurueck
     * @return das zugrundeliegende Credentials Objekt
     */
    public org.web3j.crypto.Credentials getRawCredentials() {
        return credentials;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Credentials that = (Credentials) o;
        return credentials.equals(that.credentials) &&
                seed.equals(that.seed);
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentials, seed);
    }
}
