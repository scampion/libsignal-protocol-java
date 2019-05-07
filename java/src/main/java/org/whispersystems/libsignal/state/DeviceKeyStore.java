package org.whispersystems.libsignal.state;

import com.google.protobuf.ByteString;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public interface DeviceKeyStore {

    public PublicKey getDevicePublicKey();

    public PrivateKey getDevicePrivateKey();

    public void addDeviceKey(PublicKey pk);

    public List<ByteString> getDevicesPublicKeys();

}