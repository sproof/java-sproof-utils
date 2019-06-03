package at.ac.fhsalzburg.sproof;

import org.bitcoinj.crypto.*;
import org.bitcoinj.wallet.DeterministicKeyChain;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.core.Transaction;
import org.ethereum.crypto.ECIESCoder;
import org.ethereum.crypto.ECKey;
import org.json.JSONException;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.jcajce.provider.digest.Keccak;
import org.spongycastle.math.ec.ECPoint;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {

    private static Logger logger = LoggerFactory.getLogger(Utils.class);

    /**
     * erstellt aus den uebergebenen Daten eine SHA3 Hash
     * @param data zu hashenden Daten
     * @return der Hash der Daten
     */
    private static byte[] sha3 (byte[] data) {
        return new Keccak.Digest256().digest(data);
    }

    /**
     * ueberprueft ob es sich bei den uebergebenen Daten um eine Hash handelt oder nicht
     * @param data die zu ueberpruefenden Daten
     * @return true wenn es sich um um eine Hash handelt, sonst False
     */
    static Boolean isHash (String data) {
        Pattern pattern = Pattern.compile("[0-9A-Fa-f]*");
        Matcher matcher = pattern.matcher(data);
        return data.length() == 64 && matcher.matches();
    }

    /**
     * wandelt das Byte Array in eine hex String um und fuegt den 0x Prefix an
     * @param bytes zu bearbeitende Daten
     * @return bearbeitete Daten
     */
    private static String asHexWithPrefix(byte[] bytes) {
        return "0x" + Hex.toHexString(bytes);
    }

    /**
     * entfernt vom uebergeben String den vorangehenden Prefix 0x
     * @param str zu bearbeitender String
     * @return bearbeitete Daten
     */
    static String removeHexPrefix(String str) {
        if(str.startsWith("0x")) {
            str = str.substring(2);
        }
        return  str;
    }

    /**
     * erstellt einen SHA3 Hash aus einem uebergebenen Byte Array und fuegt den 0x Prefix an
     * @param bytes zu hashende Daten
     * @return der Hash der Daten mit 0x Prefix
     */
    public static String getHash(byte[] bytes) {
        return asHexWithPrefix(sha3(bytes));
    }

    /**
     * erstellt einen SHA3 Hash aus einem uebergebenen String und fuegt den 0x Prefix an
     * @param string zu hashende Daten
     * @return der Hash der Daten mit 0x Prefix
     */
    public static String getHash(String string) {
        return getHash(string.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * liefert die aktuelle Zeit in Sekunden zurueck
     * @return liefert die aktuelle Zeit in Sekunden zurueck
     */
    private static Long unixTimeInSeconds() {
        return Math.round(System.currentTimeMillis() / 1000.0);
    }

    /**
     * erstellt aus einem seed Zugangsdaten
     * @param seedString seed aus dem die Zugangsdaten erstellt werden sollen
     * @return die zum seed gehoerigen Zugangsdaten
     * @throws UnreadableWalletException
     */
    private static Credentials createCredentials(String seedString) throws UnreadableWalletException {
        DeterministicSeed seed = new DeterministicSeed(seedString, null, "",
                System.currentTimeMillis() / 1000);

        DeterministicKeyChain chain = DeterministicKeyChain.builder().seed(seed).build();
        List<ChildNumber> keyPath = HDUtils.parsePath("M/44H/60H/0H/0/0");
        DeterministicKey key = chain.getKeyByPath(keyPath, true);

        return new Credentials(key.getPrivKey(), seedString);
    }

    /**
     * generiert eine Salt, hasht ihn und fuegt den 0x Prefix an
     * @return der gehashte Salt mit 0x Prefix
     */
    public static String getSalt() {
        final var random = new SecureRandom();
        var bytes = new byte[256];
        random.nextBytes(bytes);
        var asHex = Hex.toHexString(bytes);
        bytes = sha3(asHex.getBytes(StandardCharsets.UTF_8));
        return asHexWithPrefix(bytes);
    }

    /**
     * erstellt aus dem Public Key eine Adresse
     * @param publicKey verwendete Public Key
     * @return erstellte Adresse
     */
    public static byte[] publicKeyToAddress(BigInteger publicKey) {
        return publicKeyToAddress(publicKey.toByteArray());
    }

    /**
     * erstellt aus dem Public Key eine Adresse
     * @param publicKey verwendete public Key
     * @return erstellte Adresse
     */
    public static byte[] publicKeyToAddress(byte[] publicKey) {
        return Arrays.copyOfRange(sha3(publicKey), 0, 20);
    }

    /**
     * generiert einen zufaelligen seed der aus 12 Woertern besteht um daraus Zugangsdaten zu erzeugen
     * @return die erzeugeten Zugangsdaten
     * @throws MnemonicException.MnemonicLengthException
     * @throws UnreadableWalletException
     */
    public static Credentials getCredentials () throws MnemonicException.MnemonicLengthException, UnreadableWalletException {
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[16];
        random.nextBytes(randomBytes);
        List<String> seed = MnemonicCode.INSTANCE.toMnemonic(randomBytes);
        String words = String.join(" ", seed);
        return createCredentials(words);
    }

    /**
     * stellt die Zugangsdaten anhand des seedes wieder her
     * @param seed seed aus dem die Zugangsdaten Wiederhergestellt werden
     * @return die zum seed gehoerigen Zugangsdaten
     * @throws UnreadableWalletException
     */
    public static Credentials restoreCredentials (String seed) throws UnreadableWalletException {
        return createCredentials(seed);
    }

    /**
     * signiert eine Nachricht mit dem Private Key durch das verwenden von ECDSA mithilfe der ECC Kurve "secp256kl"
     * @param message die zu signierende Nachricht
     * @param credentials eigene credentials mit private key
     * @return signatur der Nachricht
     * @throws NoSuchAlgorithmException
     */
    public static Signature sign (String message, Credentials credentials) throws NoSuchAlgorithmException {
        message = removeHexPrefix(message);

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

        ECDSASigner signer = new ECDSASigner();
        ECDomainParameters ecParams = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
        ECPrivateKeyParameters ecPrivate = new ECPrivateKeyParameters(credentials.getPrivateKey(), ecParams);
        signer.init(true, ecPrivate);
        BigInteger[] sigComponents = signer.generateSignature(sha3(message.getBytes()));
        Signature sig = new Signature();
        sig.setR(Hex.toHexString(sigComponents[0].toByteArray()));
        sig.setS(Hex.toHexString(sigComponents[1].toByteArray()));

        setV(message, sig, credentials.getAddress());

        return sig;
    }

    /**
     * ueberprueft ob eine bestimmte Nachricht und die Signatur dieser Nachricht zu einem bestimmten Public Key gehoert
     * @param message die zu ueberpruefende Nachricht
     * @param signature die zu ueberpruefende Signatur der Nachricht
     * @param publicKey der zu ueberpruefende Public Key
     * @return true wenn die Nachricht und Signatur der Nachricht zum Public Key gehoeren, sonst false
     */
    public static Boolean verify(String message, Signature signature, BigInteger publicKey) {
        message = removeHexPrefix(message);
        return verify(message.getBytes(), signature, publicKey);
    }

    /**
     * ueberprueft ob eine bestimmte Nachricht aus einem String und die Signatur dieser Nachricht zu einer bestimmten Adresse gehoert
     * @param message die zu ueberpruefende Nachricht
     * @param signature die zu ueberpruefende Signatur der Nachricht
     * @param address die zu ueberpruefende Adresse
     * @return true wenn die Nachricht und Signatur der Nachricht zur Adresse gehoeren, sonst false
     */
    public static Boolean verify(String message, Signature signature, String address) {
        message = removeHexPrefix(message);
        return verify(message.getBytes(), signature, address);
    }

    /**
     * ueberprueft ob eine bestimmte Nachricht aus einem Byte Array und die Signatur dieser Nachricht zu einem bestimmten Public Key gehoert
     * @param message die zu ueberpruefende Nachricht
     * @param signature die zu ueberpruefende Signatur der Nachricht
     * @param publicKey der zu ueberpruefende Public Key
     * @return true wenn die Nachricht und Signatur der Nachricht zum Public Key gehoeren, sonst false
     */
    public static Boolean verify(byte[] message, Signature signature, BigInteger publicKey) {
        BigInteger[] keys = recoverKeys(message, signature);
        for(BigInteger key : keys) {
            if(publicKey.equals(key)) {
                return true;
            }
        }
        return false;
    }

    /**
     * ueberprueft ob eine bestimmte Nachricht aus einem Byte Array und die Signatur dieser Nachricht zu einer bestimmten Adresse gehoert
     * @param message die zu ueberpruefende Nachricht
     * @param signature die zu ueberpruefende Signatur der Nachricht
     * @param address die zu ueberpruefende Adresse
     * @return true wenn die Nachricht und Signatur der Nachricht zur Adresse gehoeren, sonst false
     */
    public static Boolean verify(byte[] message, Signature signature, String address) {
        BigInteger[] keys = recoverKeys(message, signature);
        for(BigInteger key : keys) {
            String recoveredAddress = Keys.getAddress(key);
            if(address.equals(recoveredAddress)) {
                return true;
            }
        }
        return false;
    }

    /**
     * erstellt aus einer Nachricht und der dazugehoerigen Signatur vier Schluessel von denen einer der richtige ist
     * @param message die verwendete Nachricht
     * @param signature die Signatur der Nachricht
     * @return vier erzeugte Schluessel
     */
    private static BigInteger[] recoverKeys(byte[] message, Signature signature) {
        ECDSASignature esig = new ECDSASignature(Numeric.toBigInt(signature.getR()), Numeric.toBigInt(signature.getS()));
        BigInteger[] keys = new BigInteger[4];
        for(int i = 0; i < 4; i++) {
            BigInteger res = Sign.recoverFromSignature(i, esig, Hash.sha3(message));
            keys[i] = res;
        }
        return keys;
    }

    /**
     * signiert eine Transaktion mit einem Private Key aus den Zugangsdaten
     * @param rawTransaction Transaktion die signiert werden soll
     * @param credentials Zugangsdaten mit denen signiert werden soll
     * @return die signierte Transaktion
     */
    public static TxSignResult signTx(Transaction rawTransaction, Credentials credentials)
    {
        rawTransaction.sign(ECKey.fromPrivate(credentials.getPrivateKey()));
        byte[] rlpEncoded = rawTransaction.getEncoded();
        String rlpHex = Utils.asHexWithPrefix(rlpEncoded);
        String txHash = Utils.asHexWithPrefix(rawTransaction.getHash());
        return new TxSignResult(rlpHex, txHash);
    }

    /**
     * ueberpruefte ob man sich zum jetztigen Zeitpung inerhalb eines gueltigen Zeitrahmens befindet
     * @param validFrom Ausgangszeit der Gueltigkeit
     * @param validUntil Endzeit der Gueltigkeit
     * @return true wenn man sich im gueltigen Zeitrahmen befindedet, sonst false
     */
    public static Boolean isInTimeRange(Long validFrom, Long validUntil) {
        Long currentUnixTimestamp = unixTimeInSeconds();
        validFrom = validFrom!=null ? validFrom : 0;
        validUntil = validUntil!=null ? validUntil : Long.MAX_VALUE;
        return (validFrom < currentUnixTimestamp) && (currentUnixTimestamp < validUntil);
    }

    /**
     * verschluesselt einen String an Daten mit eine Public Key
     * @param publicKey der verwendete Public Key
     * @param data die zu verschluesselnden Daten als String
     * @return die verluesselten Daten
     */
    public static String encrypt(ECPoint publicKey, String data) {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] encr = ECIESCoder.encrypt(publicKey, dataBytes);
        return Base64.getEncoder().encodeToString(encr);
    }

    /**
     * entschluesselt eine String an Daten mit einem Private Key
     * @param privateKey der verwendete Private Key
     * @param data die zu entschluesselnden Daten als String
     * @return die entschluesselten Daten
     * @throws InvalidCipherTextException
     * @throws IOException
     */
    public static String decrypt(BigInteger privateKey, String data) throws InvalidCipherTextException, IOException {
        byte[] fromBase64 = Base64.getDecoder().decode(data);
        byte[] decoded = ECIESCoder.decrypt(privateKey, fromBase64);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    /**
     * gibt alle Werte aus dem Source Objekt in das Destination Objekt
     * @param source Source Objekte mit potenziell mehreren Werten
     * @param destination Nimmt alle Werte des Source Objektes auf
     * @throws JSONException
     */
    public static void addAll (JSONObject source, JSONObject destination) throws JSONException {
        for(var key : source.keySet()) {
            destination.put(key ,source.get(key));
        }
    }

    private static Boolean setV(String message, Signature signature, String address) {
        address = removeHexPrefix(address);
        BigInteger[] keys = recoverKeys(message.getBytes(), signature);
        for (int i = 0; i < keys.length; i++) {
            String recoveredAddress = Keys.getAddress(keys[i]);
            if (recoveredAddress.equals(address)) {
                signature.setV(i+27);
                return true;
            }
        }
        return false;
    }
}