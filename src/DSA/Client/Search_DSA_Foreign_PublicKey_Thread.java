package DSA.Client;

import DSA.DSA;
import DSA.SHA256;
import DSA.MessagesSend;
import DSA.MessageResponse;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.util.HashMap;

/**
 * Created by mike on 25.05.15.
 */
public class Search_DSA_Foreign_PublicKey_Thread extends Thread {

    private String name;
    private String authServerName;
    private ResultPublicKeySetter setter;

    private Socket c_socket;
    private ObjectOutputStream oos;
    private ObjectInputStream ois;

    private int port;
    private HashMap<String, BigInteger[]> publicKeyDB;
    private MessagesSend messagesSend;
    //private MessageResponse messagesResponse;

    public Search_DSA_Foreign_PublicKey_Thread(String name, int port, HashMap<String, BigInteger[]> publicKeyDB, MessagesSend msg) {
        this.name = name;
        this.port = port;
        this.publicKeyDB = publicKeyDB;
        this.messagesSend = msg;
        this.authServerName = "authServer";
    }
    public void setResultSetter(ResultPublicKeySetter setter) {
        this.setter = setter;
    }

    private void checkSignature(MessageResponse msg) throws Exception {
        /* Challenge Response Check --> use values from MessagesSend */

        String nameA = this.messagesSend.getNameA();
        String nameB = this.messagesSend.getNameB();
        int logTime = msg.getLogTime(); // different value: MessagesSend
        BigInteger[] sig = msg.getSig();
        SHA256 sha = new SHA256();

        String checkMessage = this.authServerName + nameA + nameB + Integer.toString(logTime);

        if (this.publicKeyDB.containsKey(sha.hex2String(sha.calculateHash(this.authServerName)))) {
            System.out.println(this.getClass().getName() + " checkSignature() FOUND:" + this.authServerName + "--> publicKeyDB");
            BigInteger[] publicKey = this.publicKeyDB.get(sha.hex2String(sha.calculateHash(this.authServerName)));

            DSA dsa = new DSA(publicKey[0], publicKey[1], publicKey[2]);
            dsa.setPublicKey(publicKey[3]);
            if ( ! dsa.verify(checkMessage, sig)) {
                throw new Exception(this.getClass().getName() + " checkSignature() ERROR: Signature check fails");
            }
        } else {
            throw new Exception(this.getClass().getName() + " checkSignature() ERROR: publicKey:" + this.authServerName + "--> not found");
        }
    }
    public void checkLogicalTime(MessageResponse msg) throws Exception {
        if (this.messagesSend.getLogTime() >= msg.getLogTime()) {
            throw new Exception(this.getClass().getName() + " checkLogicalTime() ERROR: logTime not correct");
        }
    }

    public void run() {
        try {
            System.out.println(this.getName() + " Open Socket.....");
           c_socket = new Socket("localhost", this.port);

           oos = new ObjectOutputStream(c_socket.getOutputStream());
           ois = new ObjectInputStream(c_socket.getInputStream());
           if (! publicKeyDB.containsKey(this.name)) {

               System.out.println(this.getName() + " Write to socket ......");
               System.out.println(this.getName() + " Write to socket Messages size:" + this.messagesSend.sizeof());

               oos.writeObject(this.messagesSend);

               System.out.println(this.getName() + " Read answer from socket ......");
               MessageResponse messagesResponse = (MessageResponse) ois.readObject();
               System.out.println(this.getName() + " Read answer from socket Messages size:" + messagesResponse.sizeof());
               System.out.println(this.getClass().getName() + " run() receivedMessages --> checkSignature()....");
               checkSignature(messagesResponse);
               System.out.println(this.getClass().getName() + " run() receivedMessages Signature: OK");
               System.out.println(this.getClass().getName() + " run() receivedMessages --> checkLogicalTime()....");
               checkLogicalTime(messagesResponse);
               System.out.println(this.getClass().getName() + " run() receivedMessages logicalTime: OK");
               publicKeyDB.put(messagesResponse.getNameB(), messagesResponse.getPublicKey());
            }
            this.setter.setResultSetter(publicKeyDB);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

