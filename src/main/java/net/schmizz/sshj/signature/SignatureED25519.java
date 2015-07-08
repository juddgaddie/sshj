package net.schmizz.sshj.signature;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.schmizz.sshj.common.Buffer;
import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.vrallev.java.ecc.fast.Ecc25519HelperFast;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;

public class SignatureED25519 implements Signature {

    private EdDSAEngine edDsaEngine;

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
        this.edDsaEngine = new EdDSAEngine();
        try {
            if (pubkey != null) {
                this.edDsaEngine.initVerify(pubkey);
            }
            if (prvkey != null) {
                this.edDsaEngine.initSign(prvkey);
            }
        } catch (InvalidKeyException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public void update(byte[] H) {
        update(H, 0, H.length);
    }

    @Override
    public void update(byte[] H, int off, int len) {
        try {
            this.edDsaEngine.update(H, off, len);
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public byte[] sign() {
        try {
            return this.edDsaEngine.sign();
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }

    @Override
    public byte[] encode(byte[] signature) {
        return new byte[0];
    }

    @Override
    public boolean verify(byte[] sig) {
        System.out.println(Arrays.toString(sig));
        byte[] r;
        byte[] s;
        try {
            Buffer sigbuf = new Buffer.PlainBuffer(sig);
            final String algo = sigbuf.readString();
            if (!"ssh-ed25519".equals(algo)) {
                throw new SSHRuntimeException(String.format("Signature :: ssh-ed25519 expected, got %s", algo));
            }

            byte[] signature = sigbuf.readBytes();
            return this.edDsaEngine.verify(signature);
        } catch (Exception e) {
            throw new SSHRuntimeException(e);
        }
    }
}
