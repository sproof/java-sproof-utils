package at.ac.fhsalzburg.sproof;

import org.bitcoinj.wallet.UnreadableWalletException;


public class main {
    public static void main (String[] args) throws UnreadableWalletException {
        String seed = "symptom furnace insect easy egg rubber lend boil shell beauty february remind";
        Credentials cred = Utils.restoreCredentials(seed);
        System.out.println(cred.getPrivateKey().toString(16));
        System.out.println(cred.getPublicKey().toString(16));
        System.out.println(cred.getPublicKey().toByteArray().length);
        System.out.println(cred.getAddress());
        String m = "foobar";
//        Signature sig = Utils.sign(m, cred);
        Signature sig = new Signature();
        sig.setR("44c615561bd3a4b6fc1029fe5ea6d91cf9b17fda07bff186b3939b42a7574fb1");
        sig.setS("fb829e6cce56466323a6bffabee423bed0c36f8e9c739a19d7d2a1fcfa344523");
        sig.setV(0);
 //       System.out.println(sig.getR());
 //       System.out.println(sig.getS());
 //       System.out.println(sig.getV());
 //       System.out.println(sig.getS().length());
        System.out.println(Utils.verify(m, sig, cred.getPublicKey()));
    }
}
