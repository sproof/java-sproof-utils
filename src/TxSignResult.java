package io.sproof;

/**
 * Containerklasse fuer eine signierte Transaktion und deren Hash in HEX Format
 */
public class TxSignResult {

    private String signedTx;
    private String txHash;

    public TxSignResult(String signedTx, String txHash) {
        this.signedTx = signedTx;
        this.txHash = txHash;
    }

    /**
     * liefert einen HEX String der RLP-kodierten, signierten Transaktion zurueck
     * @return ein HEX String der RLP-kodierten, signierten Transaktion
     */
    public String getSignedTx() {
        return signedTx;
    }

    /**
     * liefert einen HEX String des hashes der signierten Transaktion zurueck
     * @return ein HEX String des hashes der signierten Transaktion
     */
    public String getTxHash() {
        return txHash;
    }
}
