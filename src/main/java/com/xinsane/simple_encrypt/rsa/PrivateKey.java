package com.xinsane.simple_encrypt.rsa;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class PrivateKey {
    private BigInteger n;
    private BigInteger d;
    private int length;

    PrivateKey(BigInteger n, BigInteger d, int length) {
        this.n = n;
        this.d = d;
        this.length = length;
    }

//    List<byte[]> list_dest = new ArrayList<>();
//    List<byte[]> list_src = new ArrayList<>();

    public byte[] decrypt(byte[] bytes) {
        int fragment_len = length / 8;
        int fragment_num = (bytes.length + fragment_len - 1) / fragment_len;
        List<byte[]> list = new ArrayList<>();
        int length = 0;
        for (int i = 0; i < fragment_num; ++i) {
            byte[] src_fragment = new byte[fragment_len];
            System.arraycopy(bytes, i*fragment_len, src_fragment, 0, fragment_len);
//            list_src.add(src_fragment);
            byte[] fragment = decrypt(new BigInteger(1, src_fragment)).toByteArray();
//            list_dest.add(fragment);
            int len = ((fragment[fragment.length-1] & 0xff) << 8) + fragment[fragment.length-2] & 0xff;
            byte[] fragment_bytes = new byte[len];
            System.arraycopy(fragment, fragment[0] == 0 ? 1 : 0, fragment_bytes, 0, len);
            list.add(fragment_bytes);
            length += fragment_bytes.length;
        }
        byte[] result = new byte[length];
        for (int i = 0; i < list.size(); ++i) {
            byte[] fragment = list.get(i);
            System.arraycopy(fragment, 0, result, i * (fragment_len - 3), fragment.length);
        }
        return result;
    }

    private BigInteger decrypt(BigInteger data) {
        return data.modPow(d, n);
    }
}
