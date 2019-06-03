package at.ac.fhsalzburg.sproof;

/**
 * Containerklasse fuer die Teile einer Signatur (r,s,v)
 */
public class Signature {
    private String r;
    private String s;
    private Integer v;

    /**
     * erstellt eine leere Signatur
     */
    public Signature() {
    }

    /**
     * erstellt eine neue Signatur mit den gegebenen Initialwerten
     * @param r HEX String von r
     * @param s HEX String von s
     * @param v Wert von v
     */
    public Signature(String r, String s, Integer v) {
        this.r = r;
        this.s = s;
        this.v = v;
    }

    public String getR() {
        return r;
    }

    public void setR(String r) {
        this.r = r;
    }

    public String getS() {
        return s;
    }

    public void setS(String s) {
        this.s = s;
    }

    public Integer getV() {
        return v;
    }

    public void setV(Integer v) {
        this.v = v;
    }
}
