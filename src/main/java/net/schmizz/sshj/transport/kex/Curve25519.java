package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.Message;
import net.schmizz.sshj.common.SSHPacket;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.Digest;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

public class Curve25519 implements KeyExchange {

    /** Named factory for DHG14 key exchange */
    public static class Factory implements net.schmizz.sshj.common.Factory.Named<KeyExchange> {

        @Override
        public KeyExchange create() {
            return new Curve25519();
        }

        @Override
        public String getName() {
            return "curve25519-sha256@libssh.org";
        }
    }


    @Override
    public void init(Transport trans, String V_S, String V_C, byte[] I_S, byte[] I_C) throws GeneralSecurityException, TransportException {

    }

    @Override
    public byte[] getH() {
        return new byte[0];
    }

    @Override
    public BigInteger getK() {
        return null;
    }

    @Override
    public Digest getHash() {
        return null;
    }

    @Override
    public PublicKey getHostKey() {
        return null;
    }

    @Override
    public boolean next(Message msg, SSHPacket buffer) throws GeneralSecurityException, TransportException {
        return false;
    }
}
