package com.xinsane.simple_encrypt.rsa;

public class RsaKey {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    RsaKey(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
