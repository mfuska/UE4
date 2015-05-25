package DSA;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by mike on 25.05.15.
 */

public class RSA {

    private final static Boolean DEBUG = false;
    private BigInteger d;
    private BigInteger e;
    private BigInteger n;

    public RSA() {
        SecureRandom random = new SecureRandom();

        int BITLENGTH = 2048;

        BigInteger p = BigInteger.probablePrime(BITLENGTH, random);
        BigInteger q = BigInteger.probablePrime(BITLENGTH, random);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        n = p.multiply(q);
        e = new BigInteger("65537"); // 2^16 + 1
        d = e.modInverse(phi);

        if (DEBUG) {
            System.out.println("p:" + p);
            System.out.println("q:" + q);
            System.out.println("n:" + n);
            System.out.println("e:" + e);
            System.out.println("d:" + d);
        }
    }
    public RSA(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }

    public RSA(String n, String e) {
        this.n = new BigInteger(n);
        this.e = new BigInteger(e);
    }
    protected void setPrivateKey(BigInteger d) {
        this.d = d;
    }
    public BigInteger getE() {
        return this.e;
    }
    public BigInteger getN() {
        return this.n;
    }
    public String getRSAParameter() {
        return new String(this.n.toString() + " " + this.e.toString() + " " + this.d.toString());
    }
    /*public BigInteger[] getPublicKey() {
        BigInteger array[] = {this.n, this.e};
        return array;
    }*/

    public String decrypt(BigInteger encrypted) {
        //return new String((encrypted.modPow(this.d, this.n)).toByteArray());
        return new String(String.valueOf(encrypted.modPow(this.d, this.n)));
    }

    public BigInteger sign(BigInteger message) {
        return message.modPow(this.d, this.n);
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(this.e, this.n);
    }

    public BigInteger verify(BigInteger signature) {
        return signature.modPow(this.e, this.n);
    }

}

