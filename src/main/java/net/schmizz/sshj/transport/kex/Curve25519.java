package net.schmizz.sshj.transport.kex;

import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.math.GroupElement;
import net.i2p.crypto.eddsa.spec.EdDSAGenParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.schmizz.sshj.common.*;
import net.schmizz.sshj.signature.*;
import net.schmizz.sshj.transport.Transport;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.digest.Digest;
import net.schmizz.sshj.transport.digest.SHA512;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class Curve25519 implements KeyExchange {
    private static final Logger log = LoggerFactory.getLogger(Curve25519.class);

    private Transport trans;
    private String V_S;
    private String V_C;
    private byte[] I_S;
    private byte[] I_C;
    private KeyPair ephemeralClientKeyPair;
    private PublicKey hostKey;
    private Digest sha512 = new SHA512();
    private byte[] H;
    private byte[] K;

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
        this.trans = trans;
        this.V_S = V_S;
        this.V_C = V_C;
        this.I_S = I_S;
        this.I_C = I_C;

        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        keyPairGenerator.initialize(new EdDSAGenParameterSpec(EdDSANamedCurveTable.CURVE_ED25519_SHA512), new SecureRandom());
        ephemeralClientKeyPair = keyPairGenerator.generateKeyPair();
        EdDSAPublicKey aPublic = (EdDSAPublicKey) ephemeralClientKeyPair.getPublic();
        trans.write(new SSHPacket(Message.KEXDH_INIT).putBytes(aPublic.getAbyte()));
        sha512.init();
    }

    @Override
    public byte[] getH() {
        return Arrays.copyOf(H, H.length);
    }

    @Override
    public BigInteger getK() {
        return new BigInteger(K);
    }

    @Override
    public Digest getHash() {
        return sha512;
    }

    @Override
    public PublicKey getHostKey() {
        return hostKey;
    }

    @Override
    public boolean next(Message msg, SSHPacket packet) throws GeneralSecurityException, TransportException {
        if (msg != Message.KEXDH_31) {
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED, "Unexpected packet: " + msg);
        }

        log.debug("Received SSH_MSG_KEXDH_REPLY");
        final byte[] K_S;
        final BigInteger f;
        final byte[] sig; // signature sent by server
        try {
            K_S = packet.readBytes();
            f = packet.readMPInt();
            sig = packet.readBytes();
            hostKey = new Buffer.PlainBuffer(K_S).readPublicKey();
        } catch (Buffer.BufferException be) {
            throw new TransportException(be);
        }

        GroupElement a = ((EdDSAPrivateKey) ephemeralClientKeyPair.getPrivate()).getA();
        a.precompute(true);
        K = a.scalarMultiply(((EdDSAPublicKey) hostKey).getAbyte()).toByteArray();

        final Buffer.PlainBuffer buf = new Buffer.PlainBuffer()
                .putString(V_C)
                .putString(V_S)
                .putString(I_C)
                .putString(I_S)
                .putString(K_S)
                .putBytes(a.toByteArray())
                .putMPInt(f)
                .putBytes(K);

        net.schmizz.sshj.signature.Signature signature = net.schmizz.sshj.common.Factory.Named.Util.create(trans.getConfig().getSignatureFactories(),
                KeyType.fromKey(hostKey).toString());
        signature.init(hostKey, null);
        signature.update(buf.array(), buf.rpos(), buf.available());

        if (!signature.verify(sig))
            throw new TransportException(DisconnectReason.KEY_EXCHANGE_FAILED,
                    "KeyExchange signature verification failed");
        return true;
    }
}
