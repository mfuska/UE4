package DSA.DSA_PublicKey_Server;

import DSA.SHA256;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;

/**
 * Created by mike on 25.05.15.
 */


public class DSA_PublicKey_Server {
    private static final int PORT = 50001;
    private static ServerSocket s_Socket;
    private static HashMap<String, BigInteger[]> publicKeyDB;

    private static BigInteger[] privateKey;

    private final static String name = "authServer";
    private static final String keyDBFile = "/Volumes/Daten/Users/mike/2sem/Kryptographische Protokolle/UE4/UE4/src/DSA/DSA_PublicKey_Server/publicKey.db";
    private static final String privateKeyDBFile = "/Volumes/Daten/Users/mike/2sem/Kryptographische Protokolle/UE4/UE4/src/DSA/DSA_PublicKey_Server/authServerPrivateKey.db";

    private static int logTime;

    public DSA_PublicKey_Server() {
        logTime = 0;
    }

    private static void initPublicKeyDB() throws IOException {
        publicKeyDB = new HashMap<String, BigInteger[]>();
        File file = new File(keyDBFile);
        BufferedReader in = new BufferedReader(new FileReader(file));
        String line = null;
        while ((line = in.readLine()) != null) {
            String[] strArray = line.split(" ");
            BigInteger[] bigArray = {
                new BigInteger(strArray[1]),
                new BigInteger(strArray[2]),
                new BigInteger(strArray[3]),
                new BigInteger(strArray[4])
            };
            publicKeyDB.put(strArray[0], bigArray);
        }
    }
    private static void readPrivateKey() throws Exception {
        File file = new File(privateKeyDBFile);
        BufferedReader in = null;
        SHA256 sha = new SHA256();
        in = new BufferedReader(new FileReader(file));
        String line = in.readLine();
        String[] strArray = line.split(" ");
        if ( strArray[0].equals(sha.hex2String(sha.calculateHash(name)))) {
           privateKey = new BigInteger[] {
                        new BigInteger(strArray[1]),
                        new BigInteger(strArray[2]),
                        new BigInteger(strArray[3]),
                        new BigInteger(strArray[4])
            };
        } else {
           throw new Exception("DSA_PublicKey_Server readPrivateKey() ERROR: readPrivateKey could not find");
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println("DSA_PublicKey_Server: started");
            System.out.println("DSA_PublicKey_Server: readPrivateKey");
            readPrivateKey();
            System.out.println("DSA_PublicKey_Server: load public KeyDB");
            initPublicKeyDB();
            s_Socket = new ServerSocket(PORT);
            System.out.println("DSA_PublicKey_Server: wait of connections on Port: " + PORT);
            while (true) {

                ResultLogicalTime setter = new ResultLogicalTime() {
                    public void setResultSetter(int logicalTime) {
                        logTime = logicalTime;
                    }
                };

                Socket s_incoming = s_Socket.accept();
                System.out.println("DSA_PublicKey_Server: accept connection on Port: " + PORT);


                DSA_PublicKey_Server_Thread t = new DSA_PublicKey_Server_Thread(s_incoming, privateKey, publicKeyDB, logTime);
                t.setName("DSA_PublicKey_Server_Thread");
                t.setResultSetter(setter);

                System.out.println("START DSA_PublicKey_Server_Thread .........");
                t.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                System.out.println("DSA_PublicKey_Server: socket closed");
                s_Socket.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }
}

