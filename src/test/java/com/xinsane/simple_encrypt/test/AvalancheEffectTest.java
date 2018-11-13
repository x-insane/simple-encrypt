package com.xinsane.simple_encrypt.test;

import com.xinsane.simple_encrypt.rsa.PublicKey;
import com.xinsane.simple_encrypt.rsa.RsaKeyGenerator;
import com.xinsane.simple_encrypt.s_des.SDesKey;
import org.junit.Test;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import java.util.Random;

public class AvalancheEffectTest {

    @Test
    public void s_des_key() {
        System.out.println("-- BEGIN S-DES KEY TEST --");
        short key = (short) 0b1101111101;
        SDesKey des = new SDesKey(key);
        byte[] origin = des.encrypt(origin_text.getBytes());
        System.out.println("cipher length: " + origin.length * 8);
        System.out.println("key\tcipher");
        for (int i = 1; i < 5; ++ i)
            System.out.println(i + "\t" + diff(origin, new SDesKey(key_diff(key, i)).encrypt(origin_text.getBytes())));
        System.out.println("--- END S-DES KEY TEST ---\n");
    }

    @Test
    public void s_des_data() {
        System.out.println("-- BEGIN S-DES DATA TEST --");
        byte key = (byte) 0b1101111101;
        SDesKey des = new SDesKey(key);
        byte[] data = new byte[]{ origin_text.getBytes()[6] };
        byte[] origin = des.encrypt(data);
        System.out.println("cipher length: " + origin.length * 8);
        System.out.println("data\tcipher");
        // print_data(data);
        for (int i = 1; i < 5; ++ i) {
            byte[] diff = data_diff(data, i);
            // print_data(diff);
            System.out.println(i + "\t\t" + diff(origin, des.encrypt(diff)));
        }
        System.out.println("--- END S-DES DATA TEST ---\n");
    }

    @Test
    public void rsa_data() {
        System.out.println("-- BEGIN RSA DATA TEST --");
        PublicKey key = RsaKeyGenerator.generate(1024).getPublicKey();
        byte[] origin = key.encrypt(origin_text.getBytes());
        System.out.println("cipher length: " + origin.length * 8);
        System.out.println("data\tcipher");
        for (int i = 1; i < 20; ++ i) {
            byte[] diff = data_diff(origin_text.getBytes(), i);
            System.out.println(i + "\t\t" + diff(origin, key.encrypt(diff)));
        }
        System.out.println("--- END RSA DATA TEST ---\n");
    }

    public static void main(String[] ars) {
        Result result = JUnitCore.runClasses(AvalancheEffectTest.class);
        System.out.println();
        for (Failure failure : result.getFailures())
            System.err.println(failure.toString());
        if (result.wasSuccessful())
            System.out.println("All tests okay.");
    }

    private int diff(byte[] s1, byte[] s2) {
        int diff = 0;
        int length = Math.min(s1.length, s2.length);
        for (int i = 0; i < length; ++i) {
            byte compare = (byte) (s1[i] ^ s2[i]);
            for (int j = 0; j < 8; ++j) {
                if ((compare & (1 << j)) != 0)
                    diff ++;
            }
        }
        return diff + Math.abs(s1.length - s2.length) * 8;
    }

    private short key_diff(short origin, int bit) {
        Random random = new Random(System.currentTimeMillis());
        boolean[] used = new boolean[10];
        int r;
        for (int i = 0; i < bit; ++ i) {
            do r = random.nextInt(10);
            while (used[r]);
            used[r] = true;
            origin ^= 1 << r;
        }
        return origin;
    }

    private byte byte_diff(byte origin, int bit) {
        Random random = new Random(System.currentTimeMillis());
        boolean[] used = new boolean[8];
        int r;
        for (int i = 0; i < bit; ++ i) {
            do r = random.nextInt(8);
            while (used[r]);
            used[r] = true;
            origin ^= 1 << r;
        }
        return origin;
    }

    private byte[] data_diff(byte[] origin, int bit) {
        Random random = new Random(System.currentTimeMillis());
        byte[] res = new byte[origin.length];
        System.arraycopy(origin, 0, res, 0, origin.length);
        boolean[] used = new boolean[origin.length];
        int r;
        for (int i = 0; i < bit; ) {
            do r = random.nextInt(origin.length);
            while (used[r]);
            used[r] = true;
            int bits = Math.min(bit - i, 8);
            res[r] = byte_diff(origin[r], bits);
            i += bits;
        }
        return res;
    }

//    private void print_data(byte[] data) {
//        for (byte b : data) {
//            System.out.print((b & 0b10000000) == 0 ? 0 : 1);
//            System.out.print((b & 0b1000000) == 0 ? 0 : 1);
//            System.out.print((b & 0b100000) == 0 ? 0 : 1);
//            System.out.print((b & 0b10000) == 0 ? 0 : 1);
//            System.out.print((b & 0b1000) == 0 ? 0 : 1);
//            System.out.print((b & 0b100) == 0 ? 0 : 1);
//            System.out.print((b & 0b10) == 0 ? 0 : 1);
//            System.out.print((b & 0b1) == 0 ? 0 : 1);
//        }
//        System.out.println();
//    }

    private static final String origin_text = "hello world! hello world! hello world!";
}
