package DSA;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Created by mike on 04.06.15.
 */
public class MessageResponse extends MessagesSend implements Serializable {
    private BigInteger[] publicKey;

    public MessageResponse(String nameA, String nameB, int logTime, BigInteger[] sig, BigInteger[] publicKey) {
        super(nameA, nameB, logTime, sig);
        this.publicKey = publicKey;
    }
    public BigInteger[] getPublicKey() {
        return publicKey;
    }
}
