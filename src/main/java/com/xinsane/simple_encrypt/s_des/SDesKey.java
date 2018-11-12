package com.xinsane.simple_encrypt.s_des;

public class SDesKey {
    private byte k1, k2;

    public SDesKey(int key) {
        key = P10((short) key);
        byte lk = LS1((byte) ((key & 0b1111100000) >> 5));
        byte rk = LS1((byte) (key & 0b11111));
        k1 = P8((short) (lk << 5 | rk));
        lk = LS1(LS1(lk));
        rk = LS1(LS1(rk));
        k2 = P8((short) (lk << 5 | rk));
    }

    public byte[] encrypt(byte[] data) {
        return crypt(data, k1, k2);
    }

    public byte[] decrypt(byte[] data) {
        return crypt(data, k2, k1);
    }

    private byte[] crypt(byte[] data, byte k1, byte k2) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; ++i) {
            byte m = IP(data[i]);
            byte lm = (byte) ((m & 0b11110000) >> 4);
            byte rm = (byte) (m & 0b1111);
            lm = (byte) (F(rm, k1) ^ lm);
            rm = (byte) (F(lm, k2) ^ rm);
            result[i] = IP_REVERSE((byte) (rm << 4 | lm));
        }
        return result;
    }
    
    private byte F(byte rm, byte k) {
        byte rm2 = (byte) (EP(rm) ^ k);
        byte rml = S(S0, (byte) ((rm2 & 0b11110000) >> 4));
        byte rmr = S(S1, (byte) (rm2 & 0b1111));
        return P4((byte) (rml << 2 | rmr));
    }

    private static short P10(short key) {
        return (short) (((key & P10[0]) == 0 ? 0 : 0b1000000000) |
                        ((key & P10[1]) == 0 ? 0 : 0b100000000) |
                        ((key & P10[2]) == 0 ? 0 : 0b10000000) |
                        ((key & P10[3]) == 0 ? 0 : 0b1000000) |
                        ((key & P10[4]) == 0 ? 0 : 0b100000) |
                        ((key & P10[5]) == 0 ? 0 : 0b10000) |
                        ((key & P10[6]) == 0 ? 0 : 0b1000) |
                        ((key & P10[7]) == 0 ? 0 : 0b100) |
                        ((key & P10[8]) == 0 ? 0 : 0b10) |
                        ((key & P10[9]) == 0 ? 0 : 0b1));
    }

    private static byte P8(short key) {
        return (byte)  (((key & P8[0]) == 0 ? 0 : 0b10000000) |
                        ((key & P8[1]) == 0 ? 0 : 0b1000000) |
                        ((key & P8[2]) == 0 ? 0 : 0b100000) |
                        ((key & P8[3]) == 0 ? 0 : 0b10000) |
                        ((key & P8[4]) == 0 ? 0 : 0b1000) |
                        ((key & P8[5]) == 0 ? 0 : 0b100) |
                        ((key & P8[6]) == 0 ? 0 : 0b10) |
                        ((key & P8[7]) == 0 ? 0 : 0b1));
    }

    private static byte IP(byte data) {
        return (byte)  (((data & IP[0]) == 0 ? 0 : 0b10000000) |
                        ((data & IP[1]) == 0 ? 0 : 0b1000000) |
                        ((data & IP[2]) == 0 ? 0 : 0b100000) |
                        ((data & IP[3]) == 0 ? 0 : 0b10000) |
                        ((data & IP[4]) == 0 ? 0 : 0b1000) |
                        ((data & IP[5]) == 0 ? 0 : 0b100) |
                        ((data & IP[6]) == 0 ? 0 : 0b10) |
                        ((data & IP[7]) == 0 ? 0 : 0b1));
    }

    private static byte EP(byte data) {
        return (byte)  (((data & EP[0]) == 0 ? 0 : 0b10000000) |
                        ((data & EP[1]) == 0 ? 0 : 0b1000000) |
                        ((data & EP[2]) == 0 ? 0 : 0b100000) |
                        ((data & EP[3]) == 0 ? 0 : 0b10000) |
                        ((data & EP[4]) == 0 ? 0 : 0b1000) |
                        ((data & EP[5]) == 0 ? 0 : 0b100) |
                        ((data & EP[6]) == 0 ? 0 : 0b10) |
                        ((data & EP[7]) == 0 ? 0 : 0b1));
    }

    private static byte P4(byte data) {
        return (byte)  (((data & P4[0]) == 0 ? 0 : 0b1000) |
                        ((data & P4[1]) == 0 ? 0 : 0b100) |
                        ((data & P4[2]) == 0 ? 0 : 0b10) |
                        ((data & P4[3]) == 0 ? 0 : 0b1));
    }

    private static byte IP_REVERSE(byte data) {
        return (byte)  (((data & IP_REVERSE[0]) == 0 ? 0 : 0b10000000) |
                        ((data & IP_REVERSE[1]) == 0 ? 0 : 0b1000000) |
                        ((data & IP_REVERSE[2]) == 0 ? 0 : 0b100000) |
                        ((data & IP_REVERSE[3]) == 0 ? 0 : 0b10000) |
                        ((data & IP_REVERSE[4]) == 0 ? 0 : 0b1000) |
                        ((data & IP_REVERSE[5]) == 0 ? 0 : 0b100) |
                        ((data & IP_REVERSE[6]) == 0 ? 0 : 0b10) |
                        ((data & IP_REVERSE[7]) == 0 ? 0 : 0b1));
    }

    /**
     * @param box S盒
     * @param d 输入4位
     * @return 输出2位
     */
    private static byte S(byte[][] box, byte d) {
        return box[(d & 0b1000) >> 2 | (d & 0b1)][(d & 0b100) >> 1 | (d & 0b10) >> 1];
    }

    private static byte LS1(byte k) {
        k <<= 1;
        k |= (k & 0b100000) == 0 ? 0 : 1;
        return (byte) (k & 0b11111);
    }

    private static final short[] P10 = new short[10];
    static {
        byte[] tmp = new byte[] {3,5,2,7,4,10,1,9,8,6};
        for (int i = 0; i < 10; ++i)
            P10[i] = (short) (1 << (10 - tmp[i]));
    }
    private static final short[] P8 = new short[8];
    static {
        byte[] tmp = new byte[] {6,3,7,4,8,5,10,9};
        for (int i = 0; i < 8; ++i)
            P8[i] = (short) (1 << (10 - tmp[i]));
    }
    private static final byte[] IP = new byte[8];
    static {
        byte[] tmp = new byte[] {2,6,3,1,4,8,5,7};
        for (int i = 0; i < 8; ++i)
            IP[i] = (byte) (1 << (8 - tmp[i]));
    }
    private static final byte[] EP = new byte[8];
    static {
        byte[] tmp = new byte[] {4,1,2,3,2,3,4,1};
        for (int i = 0; i < 8; ++i)
            EP[i] = (byte) (1 << (4 - tmp[i]));
    }
    private static final byte[][] S0 = new byte[][] {
            {1,0,3,2},
            {3,2,1,0},
            {0,2,1,3},
            {3,1,3,2}
    };
    private static final byte[][] S1 = new byte[][] {
            {0,1,2,3},
            {2,0,1,3},
            {3,0,1,0},
            {2,1,0,3}
    };
    private static final byte[] P4 = new byte[4];
    static {
        byte[] tmp = new byte[] {2,4,3,1};
        for (int i = 0; i < 4; ++i)
            P4[i] = (byte) (1 << (4 - tmp[i]));
    }
    private static final byte[] IP_REVERSE = new byte[8];
    static {
        byte[] tmp = new byte[] {4,1,3,5,7,2,8,6};
        for (int i = 0; i < 8; ++i)
            IP_REVERSE[i] = (byte) (1 << (8 - tmp[i]));
    }
}
