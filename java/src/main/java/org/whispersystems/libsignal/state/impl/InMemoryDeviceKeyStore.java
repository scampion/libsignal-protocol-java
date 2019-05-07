package org.whispersystems.libsignal.state.impl;

import com.google.protobuf.ByteString;

import org.whispersystems.libsignal.state.DeviceKeyStore;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class InMemoryDeviceKeyStore implements DeviceKeyStore {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Set<PublicKey> allDevicesKeys = new HashSet<PublicKey>();


    public InMemoryDeviceKeyStore(KeyPair keyPair) {
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    public InMemoryDeviceKeyStore() {

    }

    public PublicKey getDevicePublicKey() {
        return publicKey;
    }

    public PrivateKey getDevicePrivateKey() {
        return privateKey;
    }


    public List<ByteString> getDevicesPublicKeys(){
        List<ByteString> keys = new ArrayList<ByteString>();
        for(PublicKey pk : allDevicesKeys){
                keys.add(ByteString.copyFrom(pk.getEncoded()));
        }
        return keys;
    }

    public void addDeviceKey(PublicKey pk){
        allDevicesKeys.add(pk);
    }
}