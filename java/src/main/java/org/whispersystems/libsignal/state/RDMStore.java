package org.whispersystems.libsignal.state;

import com.google.protobuf.ByteString;
import org.whispersystems.libsignal.SignalProtocolAddress;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public interface RDMStore extends SignalProtocolStore, DeviceKeyStore {

    public byte[] join(PublicKey newDevicePublicKey);
    public void decJoin(ArrayList<byte[]> messages);
    public byte[] enc_add_join(SignalProtocolAddress ad);
    public void dec_add_join(byte[] m);
    public byte[] add(SignalProtocolAddress ad, List<ByteString> allEphemeralPublicKeys);
    public byte[] enc(SignalProtocolAddress ad, byte[] text);
    public void decAdd(ArrayList<byte[]> messages);
    public byte[] dec(byte[] m);
    public ArrayList<byte[]> addjoin(PublicKey newDevicePublicKey);

}
