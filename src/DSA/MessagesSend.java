package DSA;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Created by mike on 04.06.15.
 */
public class MessagesSend implements Serializable{
    private String nameA;
    private String nameB;
    private int logTime;
    private BigInteger[] sig;

    public MessagesSend(String nameA, String nameB, int logTime, BigInteger[] sig) {
        this.nameA = nameA;
        this.nameB = nameB;
        this.logTime = logTime;
        this.sig = sig;
    }
    public String getNameA() {
        return this.nameA;
    }
    public String getNameB() {
        return this.nameB;
    }
    public int getLogTime() {
        return this.logTime;
    }
    public BigInteger[] getSig() {
        return sig;
    }
}
