package DSA;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by mike on 05.03.15.
 */
public class DSA {
    private BigInteger p;  // length L (p = 1 mod q) p = kq + 1
    private BigInteger q;  // length 160 (q teilt p-1)
    private BigInteger h;  // 1 < h < p-1 und (h ^ (p-1/q) mod p) != 1
    private BigInteger g;  // == h ^ (p-1/q) mod p
    private BigInteger x;  // 1 < x < q
    private BigInteger y;  // 1 < y < q
    private int BITLENGTH = 4096;
    //private String SHA = "SHA-512";
    private String SHA = "SHA-256";

    private Boolean debug = true;
    // bereche y = g^x mod p
    // p,q,g,y veroeffentlicht
    // geheimer schluessel

    private DSA() {
        SecureRandom random = new SecureRandom();
        this.q = BigInteger.probablePrime(160, random);
        this.generateP(random);
        this.generateG(random);
        this.generateX(random);
        this.generateY();
        /*
        this.initDSA();
        */

    }
    private void initDSA(){
        this.x = new BigInteger("1356831522889923769543046806526144294004356527265419708150170860856577691387213140872722233721259259027104889941247329184501283390885295596643375392829829");
        this.y = new BigInteger("244096639084876556694016204343139064990040676028997328554206426805380585987242869587004401744736419481508335211904773253752325619242979543066978175645799");
        this.p = new BigInteger("10393954077751214712499992780393199730031677231586309600049430943184888618160796113546515144759488157243203345348864934082041936783128349761732911530115149");
        this.q = new BigInteger("1157957959370050296211761000590584685845216338317");
        this.g = new BigInteger("4684289672848615558873935953266635411681311883478488045613882682100910591652849969973475805471524137342135214690620342668630077489775258912010033677983266");

        //this.p = new BigInteger("13368566116231306037753538667530794234070322008103834359916472098579949466335308811083106456468528616528934653914585390214751316132736733292434587083074973");
        //this.q = new BigInteger("1058041536992883176168589017564102759170726601011");
        //this.g = new BigInteger("4065538879919081344892522714009301371109641606765011481813708499044101940541468364776997558143717102226898683951822286932267966396959001853309045202737397");
        //this.y = new BigInteger("7345708114268162505390765315538857990129990315565204085483387026439469147183314431119351935434514617270714043730068664910346831924016426664376909243283346");


    }
    private void generateY() {
        //y = g ^ x mod p
        this.y = this.g.modPow(this.x, this.p);
    }
    private void generateX(SecureRandom random) {
        // 1 < x < q
       do {
           this.x = new BigInteger(BITLENGTH, random);
       } while( ( (this.x.compareTo(BigInteger.ONE)) != 1) && ((this.x.compareTo(this.q)) != -1) );
    }
    private void generateG(SecureRandom random) {
        // 1 < h < p-1 und (h ^ (p-1/q) mod p) != 1
        BigInteger pow = this.p.subtract(BigInteger.ONE).divide(this.q);
        do {
            this.h = new BigInteger(BITLENGTH, random);
            if ((this.h.compareTo(BigInteger.ONE) == 1) || (this.h.compareTo(this.p.subtract(BigInteger.ONE)) == -1)) {
                this.g = h.modPow(pow, this.p);
            }
        } while ( (this.g.compareTo(BigInteger.ONE) == 0 ) && (this.g.compareTo(BigInteger.ONE) == 1) );

        if (debug) {
            System.out.println("h:" + h);
            System.out.println("h.bitLength:" + h.bitLength());
            System.out.println("g:" + g);
            System.out.println("g.bitLength:" + g.bitLength());
            System.out.println("p:" + p);
            System.out.println("p.bitLength:" + p.bitLength());
            System.out.println("q:" + q);
            System.out.println("q.bitLength:" + q.bitLength());
        }
    }


    private void generateP(SecureRandom random) {
        int steps = 0;
        BigInteger p_tmp;
        if (debug) System.out.println("testing for p");
        do {
            steps++;
            p_tmp = new BigInteger(BITLENGTH, random); // all the time new number
            if (debug) System.out.println(steps + "-> " + p_tmp);
            p_tmp = p_tmp.subtract(p_tmp.subtract(BigInteger.ONE).mod(q)); // (p - 1 = k * q) == (p -1 = 0 mod q)
        } while (! p_tmp.isProbablePrime(100) || p_tmp.bitLength() != BITLENGTH);
        this.p = p_tmp;
        if (debug) {
            System.out.println("p:" + this.p);
            System.out.println("p founded after:" + steps);
        }
    }

    public BigInteger[] getPublicKey() {
        BigInteger[] publicKey = {this.p, this.q, this.g, this.y};
        return publicKey;
    }

    public BigInteger[] sign(String m) throws NoSuchAlgorithmException {
        /*
            1< s <q
            s1 = (g^s mod p) mod q --> wenn s1 = 0 repeat
            s2 = s^-1 (SHA(m) + s1 . x) mod q -->  s2 = 0  s1 new calculate
         */
        MessageDigest sha2= MessageDigest.getInstance(this.SHA);
        BigInteger msg2sha2 = new BigInteger(sha2.digest(m.getBytes()));

        SecureRandom random = new SecureRandom();
        BigInteger s;
        BigInteger s1 = BigInteger.ZERO;
        BigInteger s2 = BigInteger.ZERO;
        do {
            s = new BigInteger(this.q.bitLength(), random);
            //compareTo:  // -1 less than // 0 equal // 1 greater than
            if (s.compareTo(BigInteger.ONE) == 1 && s.compareTo(this.q) == -1) {
                do {
                    s1 = (this.g.modPow(s, this.p)).mod(this.q);
                } while(s1.compareTo(BigInteger.ZERO) == 0);
                s2 = s.modInverse(this.q).multiply(msg2sha2.add(s1.multiply(this.x))).mod(this.q);
            }
        } while ( s2.compareTo(BigInteger.ZERO) == 0 );

        BigInteger[] signature = {s1, s2};
        if (this.debug) {
            System.out.println("s1: " + s1);
            System.out.println("s2: " + s2);
            System.out.println("s1.bitlength: " + s1.bitLength());
            System.out.println("s2.bitlength: " + s2.bitLength());
        }
        return signature;
    }

    public boolean verify(String m, BigInteger[] signatur, BigInteger[] publicKey) throws NoSuchAlgorithmException {
        /*
        geg: s1, s2 --> signatur[]
        m die nachricht
        Check:
            1. 0 < s1 < q  && 0 < s2 < q --> not True sig false

        Calulate:
            w = s2^-1 mod q
            u1 = SHA(m) mod q
            u2 = s1 mod q
            v = (g^u1 y^u2 mod p) mod q
            if (v == s1) --> sig valid
         */

        MessageDigest sha2= MessageDigest.getInstance(this.SHA);
        BigInteger sha2hash = new BigInteger(sha2.digest(m.getBytes()));

        BigInteger s1 = signatur[0];
        BigInteger s2 = signatur[1];

        BigInteger p = publicKey[0];
        BigInteger q = publicKey[1];
        BigInteger g = publicKey[2];
        BigInteger y = publicKey[3];
        // check 1: 0 < s1 < q  && 0 < s2 < q --> not True sig false
        if ( (s1.compareTo(BigInteger.ZERO) == 1 && s1.compareTo(q) == -1) &&
                (s2.compareTo(BigInteger.ZERO) == 1 && s2.compareTo(q) == -1) ) {
            BigInteger w = s2.modInverse(q);
            BigInteger u1 = sha2hash.multiply(w).mod(q);
            BigInteger u2 = s1.multiply(w).mod(q);
            BigInteger v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);

            return v.compareTo(s1) == 0;
        }
        return false;
    }
    public static void main(String[] args) {
        DSA dsa = new DSA();
        try {
            String tmp = "test der test";
            BigInteger[] array = dsa.sign(tmp);
            if (dsa.verify(tmp, array, dsa.getPublicKey())) {
                System.out.println("Verify OK");
            } else {
                System.out.println("Verify Not OK");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
