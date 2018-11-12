package com.xinsane.simple_encrypt.rsa;

import java.math.BigInteger;

public class PublicKey {
    private BigInteger n;
    private BigInteger e;
    private int length;

    PublicKey(BigInteger n, BigInteger e, int length) {
        this.n = n;
        this.e = e;
        this.length = length;
    }

//    List<byte[]> list_src = new ArrayList<>();
//    List<byte[]> list_dest = new ArrayList<>();

    public byte[] encrypt(byte[] bytes) {
        int max_len = length / 8 - 3; // 最大分片长度，首位始终留空，以防data > n
        int fragment_num = (bytes.length + max_len - 1) / max_len;
        int fragment_len = length / 8;
        byte[] result = new byte[fragment_num * fragment_len];
        for (int i = 0; i < fragment_num; ++i) {
            try {
                byte[] fragment = new byte[fragment_len-1];
                int len = i == fragment_num - 1 ? bytes.length % max_len : max_len;
                System.arraycopy(bytes, i * max_len, fragment, 0, len);
                fragment[fragment.length-2] = (byte) (len % 0x100); // 低字节填充
                fragment[fragment.length-1] = (byte) (len / 0x100); // 高字节填充
//                list_src.add(fragment);
                fragment = encrypt(new BigInteger(1, fragment)).toByteArray();
//                list_dest.add(fragment);
                int src_pos = fragment[0] == 0 ? 1 : 0;
                int copy_length = fragment.length - src_pos;
                int dest_pos_offset = fragment_len - copy_length;
                System.arraycopy(fragment, src_pos, result, i*fragment_len + dest_pos_offset, copy_length);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return result;
    }

    private BigInteger encrypt(BigInteger data) {
        return data.modPow(e, n);
    }
}
