package DSA.Client;

import DSA.DSA;

import java.math.BigInteger;
import java.util.HashMap;

/**
 * Created by mike on 25.05.15.
 */
public class ClientDSA {
    private final static int PORT = 50001;
    private final static String privateKeyFile = "/Volumes/Daten/Users/mike/2sem/Kryptographische Protokolle/UE4/UE4/src/DSA/Client/privateKey.db";

    private HashMap<String, BigInteger[]> publicKeyDB;
    private BigInteger[] privateKey;

    private String name = "michi";
    public ClientDSA() {
        this.publicKeyDB = new HashMap<String, BigInteger[]>();
        readPrivatKey(name);
        readPublicKey(name);
        String message = "Test";
        try {
            BigInteger[] sig = generateSignature(message, privateKey);
            if (checkSignature(publicKeyDB.get(name), sig, message) ) {
                System.out.print("sig check ok");
            } else {
                System.out.print("sig check ok");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    private void readPrivatKey(String name) {
        ResultPrivateKeySetter setter = new ResultPrivateKeySetter() {
            public void setResultSetter(BigInteger[] pKey) {
                privateKey = pKey;
            }
        };

        ClientInitPrivateDSAKeyThread t = new ClientInitPrivateDSAKeyThread(name, privateKeyFile );
        t.setName("ClientInitPrivateDSAKeyThread");
        t.setResultSetter(setter);
        t.start();
    }
    private void readPublicKey(String name) {
        ResultPublicKeySetter setter = new ResultPublicKeySetter() {
            public void setResultSetter(HashMap<String, BigInteger[]> pKey) {
                publicKeyDB = pKey;
            }
        };

        ClientInitPublicDSAKeyThread t = new ClientInitPublicDSAKeyThread(name, PORT, publicKeyDB );
        t.setName("ClientInitPublicDSAKeyThread");
        t.setResultSetter(setter);
        t.start();

    }
    private Boolean checkSignature(BigInteger[] dsaPublicKey, BigInteger[] sig, String message) throws Exception {
        if (dsaPublicKey.length != 4 ) {
            throw new Exception("wrong Key");
        }
        if (sig.length != 2 ) {
            throw new Exception("wrong Signature");
        }
        DSA dsa_public = new DSA(
                dsaPublicKey[0],
                dsaPublicKey[1],
                dsaPublicKey[2]
        );
        dsa_public.setPublicKey(dsaPublicKey[3]);
        return dsa_public.verify(message, sig);
    }
    private BigInteger[] generateSignature(String message, BigInteger[] dsaPrivateKey) throws Exception {
        if (dsaPrivateKey.length != 4) {
            throw new Exception("wrong Key");
        }
        DSA dsa_private = new DSA(
                dsaPrivateKey[0],
                dsaPrivateKey[1],
                dsaPrivateKey[2]
        );
        dsa_private.setPrivatKey(dsaPrivateKey[3]);
        BigInteger[] sig = dsa_private.sign(message);

        if (sig.length != 2) {
            throw new Exception("wrong Key");
        }
        return sig;
    }
    public static void main(String[] args)  {
        ClientDSA clientDSA = new ClientDSA();

    }
}

