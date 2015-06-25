package net.schmizz.sshj.signature;

import net.schmizz.sshj.common.KeyType;

import java.security.PrivateKey;
import java.security.PublicKey;

public class SignatureED25519 implements Signature {
    /** A named factory for ED25519 signature */
    public static class Factory
            implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public Signature create() {
            return new SignatureED25519();
        }

        @Override
        public String getName() {
            return KeyType.ED25519.toString();
        }

    }


    @Override
    public void init(PublicKey pubkey, PrivateKey prvkey) {

    }

    @Override
    public void update(byte[] H) {

    }

    @Override
    public void update(byte[] H, int off, int len) {

    }

    @Override
    public byte[] sign() {
        return new byte[0];
    }

    @Override
    public byte[] encode(byte[] signature) {
        return new byte[0];
    }

    @Override
    public boolean verify(byte[] sig) {
        return false;
    }
}
