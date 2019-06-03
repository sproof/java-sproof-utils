package at.ac.fhsalzburg.sproof;

import org.bitcoinj.crypto.MnemonicException;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bouncycastle.util.encoders.Hex;
import org.ethereum.crypto.HashUtil;
import org.json.simple.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.jcajce.provider.digest.Keccak;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.math.ec.ECPoint;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

public class UtilsTest {

    private String testString = "testdata";

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void isHash() {
        String testHash = "60abf4ca56b04f56cb6af04c6a5bf056abfc056ca0bfd6ab56b0cf5604bfcf0e";
        assertTrue(Utils.isHash(testHash));
    }

    @Test
    public void getHash() throws UnsupportedEncodingException {
        byte[] hashed = HashUtil.sha3(testString.getBytes(StandardCharsets.UTF_8));
        String hexString = Hex.toHexString(hashed);
        String utilsResult = Utils.getHash(testString.getBytes(StandardCharsets.UTF_8));
        assertEquals("0x" + hexString, utilsResult);
    }

    @Test
    public void getHash1() throws UnsupportedEncodingException {
        byte[] hashed = HashUtil.sha3(testString.getBytes(StandardCharsets.UTF_8));
        String hexString = Hex.toHexString(hashed);
        String utilsResult = Utils.getHash(testString);
        assertEquals("0x" + hexString, utilsResult);
    }

    @Test
    public void getSalt() {
        String salt = Utils.getSalt();
        assertTrue(salt.startsWith("0x"));
        assertEquals(66, salt.length());    // "0x" + 64 bytes
    }

    @Test
    public void publicKeyToAddress() {
        BigInteger bigInt = new BigInteger("1234567890");
        byte[] keccak = new Keccak.Digest256().digest(bigInt.toByteArray());
        byte[] utilsOutput = Utils.publicKeyToAddress(bigInt);
        byte[] keccakSubArray = Arrays.copyOfRange(keccak, 0, 20);
        assertArrayEquals(keccakSubArray, utilsOutput);
    }

    @Test
    public void getCredentials() throws MnemonicException.MnemonicLengthException, UnreadableWalletException {
        Credentials test = Utils.getCredentials();
        String addresshex = Utils.removeHexPrefix(test.getAddress());
        Pattern patternhex = Pattern.compile("[0-9A-Fa-f]*");
        Pattern patternwords = Pattern.compile("[a-z\\p{Blank}]*");
        Matcher matcherpri = patternhex.matcher(Hex.toHexString(test.getPrivateKey().toByteArray()));
        Matcher matcherpub = patternhex.matcher(Hex.toHexString(test.getPublicKey().toByteArray()));
        Matcher matcheraddr = patternhex.matcher(addresshex);
        Matcher matcherseed = patternwords.matcher(test.getSeed());
        assertEquals(42, test.getAddress().length());
        assertTrue(matcheraddr.matches());
        assertTrue(matcherpri.matches());
        assertTrue(matcherpub.matches());
        assertTrue(matcherseed.matches());
    }

    @Test
    public void restoreCredentials() throws MnemonicException.MnemonicLengthException, UnreadableWalletException {
        Credentials credentials = Utils.getCredentials();
        Credentials restored = Utils.restoreCredentials(credentials.getSeed());
        assertEquals(credentials, restored);
    }

    @Test
    public void verify2() throws NoSuchAlgorithmException, MnemonicException.MnemonicLengthException, UnreadableWalletException {
        Credentials credentials = Utils.getCredentials();
        String massage = testString;
        Signature signature = Utils.sign(massage, credentials);
        assertTrue(Utils.verify(massage, signature, credentials.getPublicKey()));
    }

    @Test
    public void verify3() throws NoSuchAlgorithmException, MnemonicException.MnemonicLengthException, UnreadableWalletException {
        Credentials credentials = Utils.getCredentials();
        String massage = testString;
        Signature signature = Utils.sign(massage, credentials);
        String address = credentials.getAddress();
        address = Utils.removeHexPrefix(address);
        assertTrue(Utils.verify(massage, signature, address));

    }

    @Test
    public void isInTimeRange() {
        long timeFrom = 1557007201l; //05.05.2019
        long timeTill = 4081615201l; //05.05.2099
        assertTrue(Utils.isInTimeRange(timeFrom, timeTill));
    }

    @Test
    public void encrypt() throws MnemonicException.MnemonicLengthException, UnreadableWalletException, IOException, InvalidCipherTextException {
        String text = "{\"a\":\"b\",\"c\":\"d\"}";
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        Credentials credentials = Utils.getCredentials();
        ECPoint pubKeyPoint = spec.getG().multiply(credentials.getPrivateKey());
        String ciphertext = Utils.encrypt(pubKeyPoint, text);

        String decrypted = Utils.decrypt(credentials.getPrivateKey(), ciphertext);
        assertEquals(text, decrypted);
    }

    @Test
    public void addAll() {
        JSONObject source = new JSONObject();
        source.put("key1", "value1");
        source.put("key2", 42);
        source.put("key3", true);

        JSONObject destination = new JSONObject();
        destination.put("key10", "value10");
        destination.put("key11", 65);

        Utils.addAll(source, destination);
        assertTrue(destination.containsKey("key1"));
        assertEquals("value1", destination.get("key1"));
        assertTrue(destination.containsKey("key2"));
        assertEquals(42, destination.get("key2"));
        assertTrue(destination.containsKey("key3"));
        assertEquals(true, destination.get("key3"));
        assertTrue(destination.containsKey("key10"));
        assertEquals("value10", destination.get("key10"));
        assertTrue(destination.containsKey("key11"));
        assertEquals(65, destination.get("key11"));
    }
}