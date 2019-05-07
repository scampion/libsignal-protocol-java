/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionStore;

import static org.whispersystems.libsignal.state.StorageProtos.RecordStructure;
import static org.whispersystems.libsignal.state.StorageProtos.AllAddressRecordStructure;
import static org.whispersystems.libsignal.state.StorageProtos.AddressRecordStructure;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class InMemorySessionStore implements SessionStore {

  private Map<SignalProtocolAddress, byte[]> sessions = new HashMap<>();

  public InMemorySessionStore() {}

    @Override
  public synchronized SessionRecord loadSession(SignalProtocolAddress remoteAddress) {
    try {
      if (containsSession(remoteAddress)) {
        return new SessionRecord(sessions.get(remoteAddress));
      } else {
        return new SessionRecord();
      }
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public synchronized List<Integer> getSubDeviceSessions(String name) {
    List<Integer> deviceIds = new LinkedList<>();

    for (SignalProtocolAddress key : sessions.keySet()) {
      if (key.getName().equals(name) &&
          key.getDeviceId() != 1)
      {
        deviceIds.add(key.getDeviceId());
      }
    }

    return deviceIds;
  }

  @Override
  public synchronized void storeSession(SignalProtocolAddress address, SessionRecord record) {
      sessions.put(address, record.serialize());
  }

  @Override
  public synchronized boolean containsSession(SignalProtocolAddress address) {
    return sessions.containsKey(address);
  }

  @Override
  public synchronized void deleteSession(SignalProtocolAddress address) {
    sessions.remove(address);
  }

  @Override
  public synchronized void deleteAllSessions(String name) {
    for (SignalProtocolAddress key : sessions.keySet()) {
      if (key.getName().equals(name)) {
        sessions.remove(key);
      }
    }
  }

    @Override
    public void load(byte[] rdm_sessions) {
        try {
            AllAddressRecordStructure all = AllAddressRecordStructure.parseFrom(rdm_sessions);
            List<AddressRecordStructure> allList = all.getAddressRecordStructureList();
            for(AddressRecordStructure item : allList){
                SignalProtocolAddress address = new SignalProtocolAddress(item.getName(), 1);
                RecordStructure recordStructure = item.getRecordStructure();
                if (sessions.containsKey(address)) {
                    recordStructure.toBuilder().mergeFrom(new SessionRecord(sessions.get(address)).getRecordStructure());
                }
                sessions.put(address, recordStructure.toByteArray());
            }
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
            //FIXME
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public Map<SignalProtocolAddress, byte[]> getAllSessions() {
      return sessions;
    }


    @Override
    public byte[] dumpSessions(boolean keepRDM) {
        List<AddressRecordStructure> allRecords = new ArrayList<AddressRecordStructure>();
        for (Map.Entry<SignalProtocolAddress, byte[]> entry : sessions.entrySet()) {
            try {
                SessionRecord sessionRecord = new SessionRecord(entry.getValue());
                if (keepRDM) {
                    sessionRecord.rdmFilterAllStates();
                } else {
                    sessionRecord.signalFilterAllStates();
                }
                AddressRecordStructure ars = AddressRecordStructure.newBuilder()
                        .setName(entry.getKey().getName())
                        .setRecordStructure(sessionRecord.getRecordStructure())
                        .build();
                allRecords.add(ars);
            } catch (InvalidProtocolBufferException e) {
                e.printStackTrace(); //FIXME
            } catch (IOException e) {
                e.printStackTrace(); //FIXME
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
        AllAddressRecordStructure allRecordByAddress = AllAddressRecordStructure.newBuilder()
                .addAllAddressRecordStructure(allRecords)
                .build();
        return allRecordByAddress.toByteArray();
    }

    @Override
    public void updateAllEphemeralPubKey(PublicKey newDevicePublicKey) {
        Map<SignalProtocolAddress, byte[]> sessions_updated = new HashMap<>();
        for (Map.Entry<SignalProtocolAddress, byte[]> entry : sessions.entrySet()) {
            SessionRecord sessionRecord = null;
            try {
                sessionRecord = new SessionRecord(entry.getValue());
                sessionRecord.getSessionState().updateAllEphemeralPublicKey(newDevicePublicKey);
                sessions_updated.put(entry.getKey(), sessionRecord.serialize());
            } catch (IOException e) {
                e.printStackTrace();
            }
            }
            sessions = sessions_updated;
        }

    @Override
    public void setOwnEphemeralKeys(PrivateKey devicePrivateKey, PublicKey devicePublicKey) {
        Map<SignalProtocolAddress, byte[]> sessions_updated = new HashMap<>();
        for (Map.Entry<SignalProtocolAddress, byte[]> entry : sessions.entrySet()) {
            SessionRecord sessionRecord = null;
            try {
                sessionRecord = new SessionRecord(entry.getValue());
                sessionRecord.getSessionState().updateOwnpheralKeys(devicePrivateKey, devicePublicKey);
                sessions_updated.put(entry.getKey(), sessionRecord.serialize());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        sessions = sessions_updated;

    }
}
