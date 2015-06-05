package DSA.Client;

import DSA.DSA;
import DSA.MessagesSend;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

/**
 * Created by mike on 25.05.15.
 */
public class ClientDSA {
    private final static int PORT = 50001;
    private final static String privateKeyFile = "/Volumes/Daten/Users/mike/2sem/Kryptographische Protokolle/UE4/UE4/src/DSA/Client/privateKey.db";
    private final static String authServerFile = "/Volumes/Daten/Users/mike/2sem/Kryptographische Protokolle/UE4/UE4/src/DSA/Client/authServerPublicKey.db";

    private HashMap<String, BigInteger[]> publicKeyDB;
    private BigInteger[] privateKey;
    private int logTime;
    private String nameA = "michi";
    private String nameB = "daniel";

    public ClientDSA() {
        this.logTime = 0;
        this.publicKeyDB = new HashMap<String, BigInteger[]>();

        readPrivateKey(nameA);
        readPublicKeyAuthServer();
        try {
            readPublicKey(this.nameA, this.nameB);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    private void readPublicKeyAuthServer() {
        ResultPublicAuthServerSetter setter = new ResultPublicAuthServerSetter() {
            public void setResultSetter(HashMap<String, BigInteger[]> pKey) {
                publicKeyDB = pKey;
            }
        };
        Init_DSA_PublicPKIKey_Thread t = new Init_DSA_PublicPKIKey_Thread(publicKeyDB, authServerFile);
        t.setName("Init_DSA_PublicPKIKey_Thread");
        t.setResultSetter(setter);
        t.start();
    }
    private void readPrivateKey(String name) {
        ResultPrivateKeySetter setter = new ResultPrivateKeySetter() {
            public void setResultSetter(BigInteger[] pKey) {
                privateKey = pKey;
            }
        };

        Init_DSA_PrivateClientKey_Thread t = new Init_DSA_PrivateClientKey_Thread(name, privateKeyFile );
        t.setName("Init_DSA_PrivateClientKey_Thread");
        t.setResultSetter(setter);
        t.start();
    }
    private void readPublicKey(String nameA, String nameB) throws NoSuchAlgorithmException {
        ResultPublicKeySetter setter = new ResultPublicKeySetter() {
            public void setResultSetter(HashMap<String, BigInteger[]> pKey) {
                publicKeyDB = pKey;
            }
        };

        DSA dsa = new DSA(privateKey[0], privateKey[1], privateKey[2]);
        dsa.setPrivatKey(privateKey[3]);
        String message = nameA + nameB + Integer.toString(logTime);
        MessagesSend msg = new MessagesSend(nameA, nameB, this.logTime, dsa.sign(message));
        Search_DSA_Foreign_PublicKey_Thread t = new Search_DSA_Foreign_PublicKey_Thread(nameB, PORT, publicKeyDB, msg);
        t.setName("Search_DSA_Foreign_PublicKey_Thread");
        t.setResultSetter(setter);
        t.start();
        try {
            t.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args)  {
        ClientDSA clientDSA = new ClientDSA();

    }
}

