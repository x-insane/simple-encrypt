package com.xinsane.simple_encrypt.test;

import com.xinsane.simple_encrypt.rsa.RsaKey;
import com.xinsane.simple_encrypt.rsa.RsaKeyGenerator;
import com.xinsane.simple_encrypt.s_des.SDesKey;
import org.junit.Test;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class SimpleStringTest {
    /**
     * RSA生成密钥参数n的位长度
     */
    private static final int rsa_length = 1024;

    /**
     * RSA MANY 测试次数
     */
    private static final int rsa_many_times = 500;

    /**
     * 用于测试RSA加解密的正确性和效率
     */
    @Test
    public void rsa() {
        System.out.println("---- BEGIN RSA TEST ----");
        long start_time = System.currentTimeMillis();
        RsaKey key = RsaKeyGenerator.generate(rsa_length);
        long start_encrypt_time = System.currentTimeMillis();
        System.out.println("load " + text.length() + " bytes data.");
        byte[] cipher = key.getPublicKey().encrypt(text.getBytes());
        System.out.println("encrypt into " + cipher.length + " bytes data.");
        long start_decrypt_time = System.currentTimeMillis();
        String decrypted_text = new String(key.getPrivateKey().decrypt(cipher));
        if (text.equals(decrypted_text))
            System.out.println("decrypted data passed.");
        else
            System.err.println("decrypted data rejected: " + decrypted_text);
        long final_time = System.currentTimeMillis();
        System.out.println();
        System.out.print("generate: "); System.out.print(start_encrypt_time - start_time); System.out.println("ms. ");
        System.out.print("encrypt : "); System.out.print(start_decrypt_time - start_encrypt_time); System.out.println("ms. ");
        System.out.print("decrypt : "); System.out.print(final_time - start_decrypt_time); System.out.println("ms. ");
        System.out.println("----  END  RSA TEST ----\n");
    }

    /**
     * 用于测试RSA加解密的稳定性
     * 在大量测试的情况下不应该出现错误或异常
     */
    @Test
    public void rsa_many() {
        System.out.println("---- BEGIN RSA MANY TEST ----");
        for (int i = 0; i < rsa_many_times; ++i) {
            RsaKey key = RsaKeyGenerator.generate(rsa_length);
            byte[] cipher = key.getPublicKey().encrypt(text.getBytes());
            String decrypted_text = new String(key.getPrivateKey().decrypt(cipher));
            if (!text.equals(decrypted_text))
                System.err.println("decrypted data rejected: " + decrypted_text);
            System.out.print(".");
            if (i % 100 == 99)
                System.out.println();
        }
        System.out.println("----  END  RSA MANY TEST ----\n");
    }

    @Test
    public void s_des() {
        System.out.println("---- BEGIN S-DES TEST ----");
        long start_time = System.currentTimeMillis();
        SDesKey key = new SDesKey(0b1101111101);
        long start_encrypt_time = System.currentTimeMillis();
        byte[] cipher = key.encrypt(text.getBytes());
        long start_decrypt_time = System.currentTimeMillis();
        String decrypted_text = new String(key.decrypt(cipher));
        long final_time = System.currentTimeMillis();
        if (text.equals(decrypted_text))
            System.out.println("decrypted data passed.");
        else
            System.err.println("decrypted data rejected: " + decrypted_text);
        System.out.print("generate: "); System.out.print(start_encrypt_time - start_time); System.out.println("ms. ");
        System.out.print("encrypt : "); System.out.print(start_decrypt_time - start_encrypt_time); System.out.println("ms. ");
        System.out.print("decrypt : "); System.out.print(final_time - start_decrypt_time); System.out.println("ms. ");
        System.out.println("----  END  S-DES TEST ----");
    }

    public static void main(String[] ars) {
        Result result = JUnitCore.runClasses(SimpleStringTest.class);
        System.out.println();
        for (Failure failure : result.getFailures())
            System.err.println(failure.toString());
        if (result.wasSuccessful())
            System.out.println("All tests okay.");
    }

    /**
     * 测试数据：6400字节字符串数据
     */
    private static final String text =
            "EEp7eq3PC5v4z1CfEqB9J2Vtvzsj9w9748j9hNXFzRh8FIqfNQ5OadUWzel7Pfzr" +
            "gZEs3wW7VEmSb3zS2YV0fcBFg8hHpoqGIHKnLdevIUMR3e2I1GnEQF4B8Y9VdJjV" +
            "1pl2O0ZLlZxk7EpIyBP8eBXHXYbqEKBWtjPuOuILgPCikhPmuaeGKhlFfMxITB2X" +
            "L1eoKWxVYLLXdaYzoQR3JEMW8rsMLgg9N6XdXXhgAdpphFX8eICErFOKw43GpC2Y" +
            "ytRVSXyaxqso4SoHK81v4XR9kdXJRmMi4NfMsNMwuQJUJoFNZ3zZq802GcqxdRd2" +
            "5gg3kbwhHuzOyh0jlYJc2Tk5heXmmBlFisx0YatoOCJq0quWlxylKA0ahkpTiKoO" +
            "eR1vSVHE5DZGtRHohBJTcCB1zDrGF8sIHkKQqkxqnbO6TRvYNxfJ3MxVNPMc3hoO" +
            "CTA9sOqlZRNxuFAfPPOkZuRKwy09OII9JbQMVet5QVWBfTy4Iu1LVAOhU12nE1kC" +
            "qqEK8IDyBhicU8ouDu57bELVf6ncDwuYbbtIB3E2yAjWMG90C9naX6au56QT0bOW" +
            "bkvmYw9qVOCuNUGHnWn5IUWak45QnKbPe4Cl0if58RbRuSWgviWhYHwGrMU0x8pG" +
            "aEPYDnqoRY7QhH4515vpTJ6eT5nwI3eXef7GQhRq2HZpvqT82ysgNEWWzCndKktN" +
            "ObUYxyHFoBKTFWctwvzsqTV5KpE02h3AsNvc8ux9ejtmYnzFKUZ2P6Vgl2SeBXzv" +
            "XoDiZ5MCMKOSnzarCno06ZZG7TaXX1oZOwzqcTdpepgGgh6jYP8L7q0oP1qBlju1" +
            "FUDyB7A0VEWiluggRBxCtLrDlDVwi37p4Pp5u0IK3DE7AIELmIo4Gsea2FSAC7pI" +
            "2Oefo0AjtsW4VHZVTjf2wYMplkpshQH3WVzuW0W8oq7y7lTzhHvQ7FqaUJMBYNQB" +
            "lks6BZNORjREF6oy57RdWB2rSC0p2irEU7ycantJ0eltRX19AjWqtezSYnMJMjl5" +
            "DrquBiUyffZ91RJDgrla4eGUcoK3pDvCv1aAkmnoU16Y867pG9axOASpHzns4fGO" +
            "jX8aqgCneoYqFcB34mTTwjxQU3lKKyCciKMf3NUvEPrstFfq0DpgIR2d2NkD7A1s" +
            "vdPjeA6tiPSDyH16gNcQSVoDJZRTFdNxkCXGpDgqaD1ReqTjnRPkN6PJ6Qo7QMmS" +
            "cxgShBzEs8qiEJGIE0oj31K7bRD1QkG6TBnn1teYvwuwcMigZGIt6SVArYlnevG6" +
            "9vTUwgSHWhV4NHDEcXZCbJcAVFpqST1mKiNB0qjaHPZPvGhH1cUUUA5k2zjbHsaF" +
            "rp2q418qZ97pRW0mlg3TNAHB0e9EYiOSa6nJpw1DUmpMfphngphUcEexbIwSv04y" +
            "QAA8JqSl6mYhxVfHLRitahRL9FyGrJCPdwrmFgg8R4iihx6ELKND8FGQFZ2OruD3" +
            "tucm2HlP6bm8CeuJbETw6WQdZRpBthfuNqR81zLwfJlNK4lIjUQy5RXXuqDgBneT" +
            "r2T6o3OCeTVBn7Kg2C0dYFfP5hAhbtR9HJZtHQ6TTysz6b3HTrBOOUWRuhRImM7t" +
            "PW4V8oboYVCqxw6Gfc1D2s0y5lqHRYETR79mJ60e7nx92InDejJUKn9Wju7S3avi" +
            "RyryONgeFGgcD1poC5liAqtxq9mHB8YghNxW9cubmYhkEZcztOyprSkuaX2IymjM" +
            "p81sVZGD1DvSFyRiPbybStpL0HTXb4GgfFyvxmye0jvRziqPQwlN2fmzTu2QjsuL" +
            "HsfiFRIDcpEuuUCuj18u5LQDpGh3dR3th3HDnwu5U8W36CxIIvo5mwzT6BmHY5SF" +
            "5akK5KNLVyKq2DV13aoA7FWODarV07wdL6rvuYxvOBcXr1kwZfGvkqdtrBgvvAWu" +
            "SbCaudX7YhYTaPUzHDLJCOj5siMsZGzpEnYQEpQrNg0JJ5XCHqd0gz9SnVwxzFJg" +
            "Optp88ijaI41I8I0VvtQvYophXCN9pUri21XHylqoQXx2veEvTh5hvkG6t9bNXe0" +
            "swxp0iWhvZiWmDxH7GfgrOFfgr2iul3epmYdH4Nf5zKAavHlR0ZIdXEFwjPwds5b" +
            "30ipRI2EuY5yGfefGc3kLG12RMRBXht815XJDnzEFRRuCb3iRWFgrrl3bgWwxrwP" +
            "Fnork8EnO6NZt70tgiynCcQzCyKOMOGfOhs6d5kYhw42JuYwUkXA8DHfeOYTut68" +
            "y0mW3aqqh0bGOZ2lf3dyxmcYsYoS8ioZvOEpy5Cz4ZsXBjCP7wGB76lhQmaq8E6H" +
            "mxgWVBNtAJsITJXwrEYEs9ZN6LmCbbcGZ32Nd7WsHKQfl0XL41kVKLeSZ9KLHyfD" +
            "uSpVIVIYHuwYYynKksiHgOIAncKx1pB3RD9PyDImRY7Mr9rELwVsF2RUloARUG4y" +
            "Pba03VRR0tx1u58LdVMrRanwa1V3qGBnk7XlHbW93x3ZZJNn2xol9TKQmnapkLRi" +
            "oqcu3eIvpeOQa89KMu8uZm3194VjvuIodlw9ubNqJDMApQgBmpD9gkYg7KK1sl5p" +
            "ETDS8JklhHaR7rZNMqOx69uzL2s2H9hAQrvAxRYc4EZPQLVgx6ilqe73fOXD9is4" +
            "rXpQ9k2mO9dvjRcVPOQAAM5RqooZhWVsgee537hTJqewXDYG2fuXixSGT4E5xmSs" +
            "FYxrqQRJDGNIcT4KoVaZ1vITkteZmeRShD69tSQYm0bjXWcvZ3TcIuYKwT1Cnio5" +
            "Tv23OD3LLKB0Z9lLxNnZXFBykOo28gdO0yNfIMoyWy0JF3kBaHQRTQYp5zxPwtj9" +
            "ThUXpFVtHKe5B0z4EDBNIsobJRCPNh8lCzDGXGhluAoeadwbV1vMNI0FL87ql1iH" +
            "KniUG3qi9cebaKO41VdCHQnFmssoY4i5sWNhxSiKuERcDHsSp7A4M8YM589gQLdT" +
            "R8GR35fNdVrxZaBGNkWYonOwJbMFRR12vQBBBv73OxZ6d56Gt3TyAMocWgMRSnN9" +
            "pyLFXwIigIItjoat0yL4h7oGlboJ7v9qkkvefHTv8dbLWL8GGuCDREWhEj74ErXA" +
            "t7EEO4pqtg6GsAfGf7g7n0eP8yx2Y92s4taTDsXxWBvWwsjT0cuPlcawddhl0dxk" +
            "WMnpZYK3XYWKZtdohSXX4Jzd0mjm6LVHM5bpODL8auw5i80eBxTc4GHssgceUulY" +
            "kMTRX4cR3ACfRTod7xGS8XPFVj5x8jqRviuK0dWcGAtp44ZhfROJKDZe4rkhTmGq" +
            "3hUej5sphXeMLfUDnhYGo82DYUXo6ww0Rxmr8ty6ncsKHu2v87xfAJmCRuZUVcaj" +
            "RBZPAFaZZhHj0DUH5My3BrXhY9CRi8ge3vFvOL7ZLl4RKZJKv8hxGmtkDp47KQbj" +
            "2ohGw5q3lBeyPWCzBQ8SXshQuilGFFdYWr7eIiyDo2IhFJXfBPl7eE6h5fM8mrOI" +
            "VxRezAr0kZRcJBOzw9X6iXqS0IePYCXZ2nW7ziu9YKhXMjeLCrpIu0sq1tmTrNi7" +
            "rTBFebYw9MpmUIyMmySB1TNsFDp9JkDLqLWa2vnSQyhuO9Tf8VbFN5Eg0KEM7HXE" +
            "kY0DnHQ2Gj2YonNWNSe5f7sGsLAtMtNmYA23E7aV4QZd9wHmHVdlsHolo5lTp3UH" +
            "IRztPxNFYWuQZ9oT49R0pt5koBtwx5a9CzsWGwXTjWPnSBBLEHRTYpm5wRxop3nx" +
            "pAbnNGEvyV7Ft5SxjmPXG9ssc6cnCX7aiNYUQF8Ih1L5uzwJuoxvdF5yYcb3tchw" +
            "hLTZDaBMhz9REgDLpFSo8oqZeYgPiLTqIUJzhkIeKwWYgOBxaGZkHtdLRas3Z2QV" +
            "g3sxJoa3P3EGebg87NitvL47bUM32eFRsgnFrXQ5NFaVFzS7N1qrS3BvKX5ozNNw" +
            "aAXQVC0gjvnuCfGrPgGnBPWbZLf2MHvEpsiMdg0nEUjxmbp9yrz1Liqumc4o3l2E" +
            "GUveyZW2nqZHKmapFnqRV7ODZ4TY2AxOhcucOrarcXhvF5aV77d98AYmsOR52psv" +
            "4Sk9WSp2gW3Ran6F58qjcWkKRzPNvxsdihNmjPt6RXGd1pfmiIwIwRKvrVvM8K79" +
            "6uCq2lQpsQlcf4NpnZ7teiQyELphkoOm31nafqyl2mAMz9OFCMPWRKXbmA1cGVob" +
            "kuZFk81X5ikKctEHcLIOV2y01veRMlHVtLO1Z003WG95QskmiRgjGUZCgIizEoID" +
            "2OnVQjUuTiBssksu6a2clgFC3L2VYEYMH8iZGu9tlSjDrmdXTIbNBALQB4UIKIl4" +
            "CsP2aQEjsJqzsfFhJV2TzjUkG7ZidSyXbtETZ4sYOVPQxR7mWxUArc6hu5OKSPWg" +
            "rNhI7hFWoXiUcO2e44fSkyzKZKYw7iYhwFwAFCYERD1J35TAObFSeCvlFY3y8iaA" +
            "2AcFD2tPGOp01AthdjF2fPPVAXrfv0hdIZngjPSDRsIwk02ifoiZOlR9aW6ZWX7w" +
            "O4x9t0miHyFDRt6nZThF1kG0EMT1S1bQ3AJ2ygxzC993YqgRTnzuR9bWtL1FXgj4" +
            "rKFw1pDHUXXInLqxoF2aHLJwhkqtsX9wobp0aQJD9iBTy1JwhYjRfFbK2JzEaDZK" +
            "dRUAyqDB2ratwJmAPnu6WFcl7frqRjNXNYhBkByLjKHj4S6xwEo2NXBCa3tkAv5q" +
            "sHMRqIwW7VZigscXkNt6vFuLxWnUy0CnTLowcBrsVHEn7ejfex0YHPj8dRvzyRNZ" +
            "YjALyj3HC6RtKiXnfsflS0VetNQrwXc3mmRJM5kMdbwmlcaIUEstITVhSe5Wf2W9" +
            "LX3VLWPZKthfIBGjzl0KYCQF7XEkrD2B8Q9rwGvhGikb3MiiC5MNIIuwjOnb1Qrz" +
            "7oOjcAbiez4erAn5syGJ7JuWSeXJn5b02iyz6E4W8cuhPsEcNzIqz6l1okGvrPX7" +
            "dLbh9DsBPdbTGjowbfIWqS5KNOYCotIHx1rpg44mY7CGvktgth6SMunSHnbThFM4" +
            "3dDypWyW4Hvs3ygwinrNrbBanZq87ypu0xEUwpijSGJwxosYcWUIYpkq2eHwCoIY" +
            "Tn8oAzlWiS4KO2RXfMTNgIhtPxpH1dmTdHYAZk8955BaANcVOzrnsLvDhkkEmvHZ" +
            "jsYab46zPC3j4Ag78AhToFY6Ar4WydK3Wdye9xOtwUFSlUfTyLohueQI50KBRC2X" +
            "1K4VvIRfNznzkqRa59WT8sre4DrxW7cv0EBBmfOSnkWix50VG6xxSPWD34YtfFoT" +
            "mMCRc8tO4XeMargyuVz0YTumTy956VCaZjra4sfkt4XQRD98CplRRxZvXqu15yWA" +
            "Ae02rZ1q0tnGbW8STNlevbDlQVceRUrjr3DuwvQRpQk5zPp2qOKsMw495oh1Wa5T" +
            "b4hlsOidTxQeuqrBVTRPXjfo5eFWUwY6sG0pOTfHRisMrbH9dJmI5Ooq0KTbsSnC" +
            "u4K5t0IzGWNqHUl0fjAIdcidkq6ajHxKWivHJYZG1MJeCxX42eyn4tdWAxSUTpD3" +
            "XS8mQlmYAie9OXTMP0OuwaE24Tqj4dwKrEq4nWZ9QbXjyNZhFPm1hn360mYmm3rG" +
            "aeXcfCGOEUdBFENRpRZ2dymmDUvipoyEKH6h9pvYfF2Th8V6aJNagdd9ilRP2NfW" +
            "fBinA24hRr0qHgYIdg3ZvIXm8LvPCDRv4h05BIgyxACSksmVF8EwlmzXaeyUVjMt" +
            "4oTaTE2gOzGU9h1AVdnI4kz7WwNR7lrAz4mBAhGsxawattU8wsJqz7xrCpWWgVmM" +
            "fH804eSpSxihT2toIbs6UTMBPYSa8GkyfpWx2wvpAUah73RlNBnMDSkRXrFbeK2t" +
            "2XEVSnizSOQ6BRHN7meuDVUFqHJOLiJl3kDTOPmMINhS8Oo4OM8XUj64E1LVV8y9" +
            "5vtx7ccaHXgwoqZoQ7VEnaq1S1fvWsYUHKt0HEQFMSZq56jDjyL5W19oZ6CrKv13" +
            "edaSMMYAaMV6jKQGyZVgB4dtqiKdML04H461rKR6SMrWbeuyYzVFaMwC9NMbEi3D" +
            "5MSNdb2vgzXyYsabzhW3mpcNAiG4d7IPaqVf8HS8aB2znEMhs0FbAE3tchhVf1dT" +
            "RZTjiHNHvcbU950pUFO5t3k4U8nvOltTQoZTUllWWCGKUVSsrmEvLsTJjUh6gbsJ" +
            "Pyp1Nk3Mxlh6l6BbMxShpt6crYlaHfyAXuYZu1G3VTRDYT60D0bS2ZFnbrwKVdLC" +
            "ODrRdzmTT18fvK5u86uGlsHypHTkfzxU3EupYFKbFEjOfMDa83rMMAaIkgrRrvlo" +
            "eawd2ZUUveTesiOECxN1mwU71FnEjAaGfKKzvHvKhXqzFhb47s7k7fyxCqXrq3O3" +
            "LqiYXvPaj38TikPvWYkRS24vIqZmgxG67KHNwdDxxm87hmRRI9GIxp7A0u97RJM5";
}
