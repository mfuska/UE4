package DSA.DSA_PublicKey_Server;

import DSA.DSA;
import DSA.SHA256;
import DSA.MessagesSend;
import DSA.MessageResponse;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

/**
 * Created by mike on 05.06.15.
 */
public class DSA_PublicKey_Server_Thread extends Thread{

    private Socket socket;
    private ObjectInputStream ois;
    private ObjectOutputStream oos;

    private HashMap<String, BigInteger[]> publicKeyDB;

    private DSA privateDSA;
    private SHA256 sha = new SHA256();

    private final static String name = "authServer";
    private ResultLogicalTime setter;
    private int logTime;

    public DSA_PublicKey_Server_Thread(Socket s, BigInteger[] privateKey, HashMap<String, BigInteger[]> publicKeyDB, int logTime) {
        this.socket = s;
        this.publicKeyDB = publicKeyDB;
        this.privateDSA = new DSA(privateKey[0], privateKey[1], privateKey[2]);
        this.privateDSA.setPrivatKey(privateKey[3]);
        this.logTime = logTime;
    }
    public void setResultSetter(ResultLogicalTime setter) {
        this.setter = setter;
    }

    private void checkSignature(MessagesSend msg) throws Exception {
        String nameA = msg.getNameA();
        String nameB = msg.getNameB();
        int logTime = msg.getLogTime();
        BigInteger[] sig = msg.getSig();

        String checkMessage = nameA + nameB + Integer.toString(logTime);

        if (publicKeyDB.containsKey(sha.hex2String(sha.calculateHash(nameA)))) {
            System.out.println(this.getClass().getName() + " checkSignature found:" + nameA + "--> publicKeyDB");
            BigInteger[] publicKey = publicKeyDB.get(sha.hex2String(sha.calculateHash(nameA)));

            DSA dsa = new DSA(publicKey[0], publicKey[1], publicKey[2]);
            dsa.setPublicKey(publicKey[3]);
            if ( ! dsa.verify(checkMessage, sig)) {
                throw new Exception(this.getClass().getName() + " checkSignature ERROR: Signature check fails");
            }
        } else {
            throw new Exception(this.getClass().getName() + " checkSignature ERROR: publicKey not found");
        }
    }
    private MessageResponse buildResponse(MessagesSend msg) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String nameA = msg.getNameA();
        String nameB = msg.getNameB();
        this.logTime = msg.getLogTime() + 1;

        String message = this.name + nameA + Integer.toString(this.logTime);
        return new MessageResponse(this.name,
                nameA,
                this.logTime,
                privateDSA.sign(message),
                publicKeyDB.get(sha.hex2String(sha.calculateHash(nameB)))
        );
    }

    private void checkLogicalTime(MessagesSend msg) throws Exception {
        if (this.logTime > msg.getLogTime()) {
            throw new Exception(this.getClass().getName() + " checkLogicalTime() ERROR: logTime is not correct");
        }
    }

    public void run() {
        try {
            System.out.println(this.getClass().getName() + ": getMMessage");
            this.ois = new ObjectInputStream(socket.getInputStream());
            this.oos = new ObjectOutputStream(socket.getOutputStream());
            MessagesSend msgReceived = (MessagesSend)ois.readObject();


            System.out.println(this.getClass().getName() + " checkSignature() --> receivedMessages ....");
            checkSignature(msgReceived);
            System.out.println(this.getClass().getName() + " checkSignature --> receivedMessages OK");

            System.out.println(this.getClass().getName() + " checkLogicalTime() --> receivedMessages ....");
            checkLogicalTime(msgReceived);
            System.out.println(this.getClass().getName() + " checkLogicalTime --> receivedMessages OK");

            System.out.println(this.getClass().getName() + " Search for " + msgReceived.getNameB() + " in publicKeyDB");

            if (publicKeyDB.containsKey(sha.hex2String(sha.calculateHash(msgReceived.getNameB())))) {
                System.out.println(this.getClass().getName() + " Found " + msgReceived.getNameB() + " in publicKeyDB");
                MessageResponse msgResponse = buildResponse(msgReceived);
                oos.writeObject(msgResponse);
            } else {
                System.out.println(this.getClass().getName() + " not found " + msgReceived.getNameB() + " in publicKeyDB");
                throw new Exception(this.getClass().getName() + " not found " + msgReceived.getNameB() + " in publicKeyDB");
            }
            this.setter.setResultSetter(this.logTime);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                System.out.println(this.getClass().getName() + ": close()");
                this.ois.close();
                this.oos.flush();
                this.oos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}