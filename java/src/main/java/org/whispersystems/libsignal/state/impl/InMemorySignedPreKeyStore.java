/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import com.google.protobuf.ByteString;

import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyStore;
import org.whispersystems.libsignal.state.StorageProtos;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class InMemorySignedPreKeyStore implements SignedPreKeyStore {

    private final Map<Integer, byte[]> store = new HashMap<>();

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        try {
            if (!store.containsKey(signedPreKeyId)) {
                throw new InvalidKeyIdException("No such signedprekeyrecord! " + signedPreKeyId);
            }

            return new SignedPreKeyRecord(store.get(signedPreKeyId));
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        try {
            List<SignedPreKeyRecord> results = new LinkedList<>();

            for (byte[] serialized : store.values()) {
                results.add(new SignedPreKeyRecord(serialized));
            }

            return results;
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        store.put(signedPreKeyId, record.serialize());
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return store.containsKey(signedPreKeyId);
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        store.remove(signedPreKeyId);
    }


    public List<StorageProtos.SignedPreKeyRecordStructure> dumpSignedPreKey() {
        List<StorageProtos.SignedPreKeyRecordStructure> allRecords = new ArrayList<StorageProtos.SignedPreKeyRecordStructure>();
        for (Map.Entry<Integer, byte[]> sp : store.entrySet()) {
            try {
                SignedPreKeyRecord pkr = new SignedPreKeyRecord(sp.getValue());
                StorageProtos.SignedPreKeyRecordStructure signedPreKeyRecordStructure = StorageProtos.SignedPreKeyRecordStructure.newBuilder()
                        .setId(sp.getKey())
                        .setPrivateKey(ByteString.copyFrom(pkr.getKeyPair().getPrivateKey().serialize()))
                        .setPublicKey(ByteString.copyFrom(pkr.getKeyPair().getPublicKey().serialize()))
                        .setSignature(ByteString.copyFrom(pkr.getSignature())).build();
                allRecords.add(signedPreKeyRecordStructure);
            } catch (IOException e) {
                e.printStackTrace(); //FIXME
            }
        }
        return allRecords;
    }
}



