/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.state.impl;

import com.google.protobuf.ByteString;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.state.StorageProtos;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Map;

public class InMemorySignalProtocolStore implements SignalProtocolStore {

  private final InMemoryPreKeyStore       preKeyStore       = new InMemoryPreKeyStore();
  private final InMemorySessionStore      sessionStore      = new InMemorySessionStore();
  private final InMemorySignedPreKeyStore signedPreKeyStore = new InMemorySignedPreKeyStore();
  private InMemoryIdentityKeyStore  identityKeyStore;

  private InMemoryDeviceKeyStore deviceStore = new InMemoryDeviceKeyStore();

  public InMemorySignalProtocolStore(IdentityKeyPair identityKeyPair, int registrationId) {
    this.identityKeyStore = new InMemoryIdentityKeyStore(identityKeyPair, registrationId);
    setupDeviceKeys();
  }

  public InMemorySignalProtocolStore() {
    setupDeviceKeys();
  }

  private void setupDeviceKeys() {
    Security.addProvider(new BouncyCastleProvider());
    KeyPairGenerator keyGen = null;
    try {
      keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
      keyGen.initialize(new ECGenParameterSpec("secp256r1"));
      KeyPair keyPair = keyGen.generateKeyPair();

//      KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES");
//      kpg.initialize(new ECGenParameterSpec("secp256r1"));
//      KeyPair keyPair = kpg.generateKeyPair();
//
//      Cipher cipher = Cipher.getInstance("ECIES");
//      cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

//      Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
//      cipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(keyPair.getPrivate(), keyPair.getPublic()));


      deviceStore = new InMemoryDeviceKeyStore(keyPair);
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
      e.printStackTrace(); //FIXME
    }
  }

  @Override
  public IdentityKeyPair getIdentityKeyPair() {
    return identityKeyStore.getIdentityKeyPair();
  }

  @Override
  public int getLocalRegistrationId() {
    return identityKeyStore.getLocalRegistrationId();
  }

  @Override
  public boolean saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
    return identityKeyStore.saveIdentity(address, identityKey);
  }

  @Override
  public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction) {
    return identityKeyStore.isTrustedIdentity(address, identityKey, direction);
  }

  @Override
  public IdentityKey getIdentity(SignalProtocolAddress address) {
    return identityKeyStore.getIdentity(address);
  }

    @Override
    public void setIdentityKeyPair(IdentityKeyPair ikp) {
        this.identityKeyStore.setIdentityKeyPair(ikp);
    }

    @Override
  public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
    return preKeyStore.loadPreKey(preKeyId);
  }

  @Override
  public void storePreKey(int preKeyId, PreKeyRecord record) {
    preKeyStore.storePreKey(preKeyId, record);
  }

  @Override
  public boolean containsPreKey(int preKeyId) {
    return preKeyStore.containsPreKey(preKeyId);
  }

  @Override
  public void removePreKey(int preKeyId) {
    preKeyStore.removePreKey(preKeyId);
  }

  @Override
  public SessionRecord loadSession(SignalProtocolAddress address) {
    return sessionStore.loadSession(address);
  }

  @Override
  public List<Integer> getSubDeviceSessions(String name) {
    return sessionStore.getSubDeviceSessions(name);
  }

  @Override
  public void storeSession(SignalProtocolAddress address, SessionRecord record) {
    sessionStore.storeSession(address, record);
  }

  @Override
  public boolean containsSession(SignalProtocolAddress address) {
    return sessionStore.containsSession(address);
  }

  @Override
  public void deleteSession(SignalProtocolAddress address) {
    sessionStore.deleteSession(address);
  }

  @Override
  public void deleteAllSessions(String name) {
    sessionStore.deleteAllSessions(name);
  }

  @Override
  public void load(byte[] allsessions) {
    sessionStore.load(allsessions);
  }

    @Override
    public Map<SignalProtocolAddress, byte[]> getAllSessions() {
        return sessionStore.getAllSessions();
    }

    @Override
  public byte[] dumpSessions(boolean keepRDM) {
    return sessionStore.dumpSessions(keepRDM);
  }

    @Override
    public void updateAllEphemeralPubKey(PublicKey newDevicePublicKey) {
        sessionStore.updateAllEphemeralPubKey(newDevicePublicKey);
    }

    @Override
    public void setOwnEphemeralKeys(PrivateKey devicePrivateKey, PublicKey devicePublicKey) {
        sessionStore.setOwnEphemeralKeys(devicePrivateKey, devicePublicKey);
    }

    @Override
  public List<StorageProtos.SignedPreKeyRecordStructure> dumpSignedPreKey() {
    return signedPreKeyStore.dumpSignedPreKey();
  }

  @Override
  public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
    return signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
  }

  @Override
  public List<SignedPreKeyRecord> loadSignedPreKeys() {
    return signedPreKeyStore.loadSignedPreKeys();
  }

  @Override
  public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
    signedPreKeyStore.storeSignedPreKey(signedPreKeyId, record);
  }

  @Override
  public boolean containsSignedPreKey(int signedPreKeyId) {
    return signedPreKeyStore.containsSignedPreKey(signedPreKeyId);
  }

  @Override
  public void removeSignedPreKey(int signedPreKeyId) {
    signedPreKeyStore.removeSignedPreKey(signedPreKeyId);
  }

  @Override
  public PublicKey getDevicePublicKey() {
    return deviceStore.getDevicePublicKey();
  }

  @Override
  public PrivateKey getDevicePrivateKey() {
    return deviceStore.getDevicePrivateKey();
  }

  @Override
  public void addDeviceKey(PublicKey pk) {
    deviceStore.addDeviceKey(pk);
  }

  @Override
  public List<ByteString> getDevicesPublicKeys() {
    return deviceStore.getDevicesPublicKeys();
  }

}
