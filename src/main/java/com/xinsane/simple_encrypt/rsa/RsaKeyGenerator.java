package com.xinsane.simple_encrypt.rsa;

import java.math.BigInteger;
import java.util.Random;

public class RsaKeyGenerator {
    private RsaKey key;

    public static RsaKey generate(int length) {
        return new RsaKeyGenerator(length).key;
    }

    private RsaKeyGenerator(int length) {
        Random random = new Random(System.currentTimeMillis());
        BigInteger p = BigInteger.probablePrime(length / 2, random);
        BigInteger q = BigInteger.probablePrime(length / 2, random);
        init(p, q, length);
    }

    private void init(BigInteger p, BigInteger q, int length) {
        // n = p * q;
        BigInteger n = p.multiply(q);

        // euler = (p-1)*(q-1)即 (n)
        BigInteger euler = p.subtract(BigInteger.ONE).multiply(
                q.subtract(BigInteger.ONE));

        // 选择公钥参数e
        BigInteger e = chooseE(euler);
        PublicKey publicKey = new PublicKey(n, e, length);

        // 生成私钥参数d
        BigInteger d = ged(euler, e).t;
        PrivateKey privateKey = new PrivateKey(n, d.mod(euler), length);

        key = new RsaKey(publicKey, privateKey);
    }

    private BigInteger chooseE(BigInteger euler) {
        // 这里以euler/4为种子，选取一个素数作为公钥
        // 也可以直接取65537
        return euler.divide(BigInteger.valueOf(4)).nextProbablePrime();
        // return BigInteger.valueOf(65537);
    }

    // 广义欧几里得除法: Generalized Euclidean Division
    private static GEDResult ged(BigInteger a, BigInteger b) {
        // 保证初始状态a>=b
        if (b.compareTo(a) > 0) {
            BigInteger tmp = a;
            a = b;
            b = tmp;
        }
        BigInteger u = BigInteger.valueOf(1), u1 = BigInteger.valueOf(0);
        BigInteger v = BigInteger.valueOf(0), v1 = BigInteger.valueOf(1);
        while (b.compareTo(BigInteger.ZERO) != 0) {
            BigInteger q = a.divide(b); // q = a / b

            BigInteger tmp = u.subtract(q.multiply(u1));
            u = u1;
            u1 = tmp; // u1 = u - q * u1; u = u1

            tmp = v.subtract(q.multiply(v1));
            v = v1;
            v1 = tmp; // v1 = v - q * v1; v = v1

            tmp = a.subtract(q.multiply(b));
            a = b;
            b = tmp; // b = a - q * b; a = b
        }
        return new GEDResult(a, u, v);
    }

    private static class GEDResult {
        BigInteger gcd;
        BigInteger s, t;
        GEDResult(BigInteger gcd, BigInteger s, BigInteger t) {
            this.gcd = gcd;
            this.s = s;
            this.t = t;
        }
    }
}
