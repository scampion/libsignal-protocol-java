package org.whispersystems.libsignal;

import junit.framework.TestCase;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.AliceSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.BobSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.RatchetingSession;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.util.guava.Optional;

import java.security.NoSuchAlgorithmException;
import java.util.*;


public class SessionCipherTest extends TestCase {

  public void testBasicSessionV3()
          throws InvalidKeyException, DuplicateMessageException,
          LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    SessionRecord aliceSessionRecord = new SessionRecord();
    SessionRecord bobSessionRecord   = new SessionRecord();

    initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());
    runInteraction(aliceSessionRecord, bobSessionRecord);
  }

  public void testMessageKeyLimits() throws Exception {
    SessionRecord aliceSessionRecord = new SessionRecord();
    SessionRecord bobSessionRecord   = new SessionRecord();

    initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
    bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

    SessionCipher     aliceCipher    = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
    SessionCipher     bobCipher      = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

    List<CiphertextMessage> inflight = new LinkedList<>();

    for (int i=0;i<2010;i++) {
      inflight.add(aliceCipher.encrypt("you've never been so hungry, you've never been so cold".getBytes()));
    }

    bobCipher.decrypt(new SignalMessage(inflight.get(1000).serialize()));
    bobCipher.decrypt(new SignalMessage(inflight.get(inflight.size()-1).serialize()));

    try {
      bobCipher.decrypt(new SignalMessage(inflight.get(0).serialize()));
      throw new AssertionError("Should have failed!");
    } catch (DuplicateMessageException dme) {
      // good
    }
  }

  public void testBasicSessionV4()
          throws InvalidKeyException, DuplicateMessageException,
          LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException
  {
    SessionRecord aliceSessionRecord = new SessionRecord();
    SessionRecord bobSessionRecord   = new SessionRecord();

    initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
    bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

    SessionCipher     aliceCipher    = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
    SessionCipher     bobCipher      = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

    byte[]            alicePlaintext = "This is a plaintext message.".getBytes();
    CiphertextMessage message        = aliceCipher.encrypt(alicePlaintext);
    byte[]            bobPlaintext   = bobCipher.decrypt(new SignalMessage(message.serialize()));

    assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));

  }

  public void testSesame1000message() throws InvalidKeyException, DuplicateMessageException,
          LegacyMessageException, InvalidMessageException, NoSessionException, UntrustedIdentityException {
    SessionRecord bobSessionRecord1 = new SessionRecord();
    SessionRecord bobSessionRecord2 = new SessionRecord();
    SessionRecord bobSessionRecord3 = new SessionRecord();
    SessionRecord alice1SessionRecordBob = new SessionRecord();
    SessionRecord alice2SessionRecordBob = new SessionRecord();
    SessionRecord alice3SessionRecordBob = new SessionRecord();
    SessionRecord alice1SessionRecordA2 = new SessionRecord();
    SessionRecord alice1SessionRecordA3 = new SessionRecord();
    SessionRecord alice2SessionRecordA1 = new SessionRecord();
    SessionRecord alice2SessionRecordA3 = new SessionRecord();
    SessionRecord alice3SessionRecordA1 = new SessionRecord();
    SessionRecord alice3SessionRecordA2 = new SessionRecord();


    initializeSessionsV3(alice1SessionRecordBob.getSessionState(), bobSessionRecord1.getSessionState());
    initializeSessionsV3(alice2SessionRecordBob.getSessionState(), bobSessionRecord2.getSessionState());
    initializeSessionsV3(alice3SessionRecordBob.getSessionState(), bobSessionRecord3.getSessionState());
    initializeSessionsV3(alice1SessionRecordA2.getSessionState(), alice2SessionRecordA1.getSessionState());
    initializeSessionsV3(alice1SessionRecordA3.getSessionState(), alice3SessionRecordA1.getSessionState());
    initializeSessionsV3(alice2SessionRecordA3.getSessionState(), alice3SessionRecordA2.getSessionState());

    SignalProtocolAddress bob_ad = new SignalProtocolAddress("+14159999999", 1);
    SignalProtocolAddress alice_ad1 = new SignalProtocolAddress("+14158888887", 1);
    SignalProtocolAddress alice_ad2 = new SignalProtocolAddress("+14158888888", 1);
    SignalProtocolAddress alice_ad3 = new SignalProtocolAddress("+14158888889", 1);

    SignalProtocolStore aliceStore1 = new TestInMemorySignalProtocolStore();
    SignalProtocolStore aliceStore2 = new TestInMemorySignalProtocolStore();
    SignalProtocolStore aliceStore3 = new TestInMemorySignalProtocolStore();
    SignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

    aliceStore1.storeSession(bob_ad, alice1SessionRecordBob);
    aliceStore1.storeSession(alice_ad2, alice1SessionRecordA2);
    aliceStore1.storeSession(alice_ad3, alice1SessionRecordA3);
    aliceStore2.storeSession(bob_ad, alice2SessionRecordBob);
    aliceStore2.storeSession(alice_ad1, alice2SessionRecordA1);
    aliceStore2.storeSession(alice_ad3, alice2SessionRecordA3);
    aliceStore3.storeSession(bob_ad, alice3SessionRecordBob);
    aliceStore3.storeSession(alice_ad2, alice3SessionRecordA2);
    aliceStore3.storeSession(alice_ad1, alice3SessionRecordA1);

    bobStore.storeSession(alice_ad1, bobSessionRecord1);
    bobStore.storeSession(alice_ad2, bobSessionRecord2);
    bobStore.storeSession(alice_ad3, bobSessionRecord3);


    SessionCipher alice1CipherBob = new SessionCipher(aliceStore1, bob_ad);
    SessionCipher alice1CipherA2 = new SessionCipher(aliceStore1, alice_ad2);
    SessionCipher alice1CipherA3 = new SessionCipher(aliceStore1, alice_ad3);

    SessionCipher alice2CipherBob = new SessionCipher(aliceStore2, bob_ad);
    SessionCipher alice2CipherA1 = new SessionCipher(aliceStore2, alice_ad1);
    SessionCipher alice2CipherA3 = new SessionCipher(aliceStore2, alice_ad3);

    SessionCipher alice3CipherBob = new SessionCipher(aliceStore3, bob_ad);
    SessionCipher alice3CipherA1 = new SessionCipher(aliceStore3, alice_ad1);
    SessionCipher alice3CipherA2 = new SessionCipher(aliceStore3, alice_ad2);

    SessionCipher BobCipherA1 = new SessionCipher(bobStore, alice_ad1);
    SessionCipher BobCipherA2 = new SessionCipher(bobStore, alice_ad2);
    SessionCipher BobCipherA3 = new SessionCipher(bobStore, alice_ad3);


    byte[] alicePlaintext = "Hello Bob !".getBytes();
    CiphertextMessage message;
    message = alice1CipherBob.encrypt(alicePlaintext);
    BobCipherA1.decrypt(new SignalMessage(message.serialize()));

    message = alice2CipherBob.encrypt(alicePlaintext);
    BobCipherA2.decrypt(new SignalMessage(message.serialize()));

    message = alice3CipherBob.encrypt(alicePlaintext);
    BobCipherA3.decrypt(new SignalMessage(message.serialize()));

    message = alice1CipherA2.encrypt(alicePlaintext);
    alice2CipherA1.decrypt(new SignalMessage(message.serialize()));

    message = alice1CipherA3.encrypt(alicePlaintext);
    alice3CipherA1.decrypt(new SignalMessage(message.serialize()));

    message = alice2CipherA3.encrypt(alicePlaintext);
    alice3CipherA2.decrypt(new SignalMessage(message.serialize()));

    List<SessionCipher> d0 = Arrays.asList(null, BobCipherA1, BobCipherA2, BobCipherA3);
    List<SessionCipher> d1 = Arrays.asList(alice1CipherBob, null, alice1CipherA2, alice1CipherA3);
    List<SessionCipher> d2 = Arrays.asList(alice2CipherBob, alice2CipherA1, null, alice2CipherA3);
    List<SessionCipher> d3 = Arrays.asList(alice3CipherBob, alice3CipherA1, alice3CipherA2, null);

    List<List<SessionCipher>> devices = Arrays.asList(d1, d2, d3);
    CiphertextMessage reply = null;
    ArrayList<CiphertextMessage> replies = new ArrayList<>(devices.size());

    byte[] msg;
    byte[] decrypt;
    for (int i = 0; i < 10000; i++) {
      String uuid = UUID.randomUUID().toString();
      Random rand = new Random();
      int index = rand.nextInt(devices.size());
      msg = uuid.getBytes();
      System.out.println("using alice cipher " + index + " - message: " + i + " : " + uuid);
      int k = 0;
      for (SessionCipher sc : devices.get(index)) {
        if (sc != null) {
          reply = sc.encrypt(msg);
          replies.add(k, reply);
          k++;
        }
      }

      k = 1;
      for (int j = 0; j < devices.size(); j++) {
        if (j != index) {
          System.out.println(j + " " +  index + 1  + " " + k);
          byte[] decrypt1 = devices.get(j).get(index + 1).decrypt(new SignalMessage(replies.get(k).serialize()));
          System.out.println(new String(decrypt1));
          k++;
          }
      }
      decrypt = d0.get(index + 1).decrypt(new SignalMessage(replies.get(0).serialize()));
      assertTrue(Arrays.equals(msg, decrypt));

      // Bob reply
      String s = new String(decrypt) + i;
      k = 0;
      for (SessionCipher sc : d0) {
        if (sc != null) {
          reply = sc.encrypt(s.getBytes());
          replies.add(k, reply);
          k++;
        }
      }

      for (int j = 0; j < devices.size(); j++) {
        decrypt = devices.get(j).get(0).decrypt(new SignalMessage(replies.get(j).serialize()));
      }
      assertTrue(Arrays.equals(decrypt, s.getBytes()));
    }
  }



  private void runInteraction(SessionRecord aliceSessionRecord, SessionRecord bobSessionRecord)
      throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException {
    SignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
    SignalProtocolStore bobStore   = new TestInMemorySignalProtocolStore();

    aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
    bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

    SessionCipher     aliceCipher    = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
    SessionCipher     bobCipher      = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

    byte[]            alicePlaintext = "This is a plaintext message.".getBytes();
    CiphertextMessage message        = aliceCipher.encrypt(alicePlaintext);
    byte[]            bobPlaintext   = bobCipher.decrypt(new SignalMessage(message.serialize()));

    assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));

    byte[]            bobReply      = "This is a message from Bob.".getBytes();
    CiphertextMessage reply         = bobCipher.encrypt(bobReply);
    byte[]            receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));

    assertTrue(Arrays.equals(bobReply, receivedReply));

    List<CiphertextMessage> aliceCiphertextMessages = new ArrayList<>();
    List<byte[]>            alicePlaintextMessages  = new ArrayList<>();

    for (int i=0;i<50;i++) {
      alicePlaintextMessages.add(("смерть за смерть " + i).getBytes());
      aliceCiphertextMessages.add(aliceCipher.encrypt(("смерть за смерть " + i).getBytes()));
    }

    long seed = System.currentTimeMillis();

    Collections.shuffle(aliceCiphertextMessages, new Random(seed));
    Collections.shuffle(alicePlaintextMessages, new Random(seed));

    for (int i=0;i<aliceCiphertextMessages.size() / 2;i++) {
      byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages.get(i).serialize()));
      assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages.get(i)));
    }

    List<CiphertextMessage> bobCiphertextMessages = new ArrayList<>();
    List<byte[]>            bobPlaintextMessages  = new ArrayList<>();

    for (int i=0;i<20;i++) {
      bobPlaintextMessages.add(("смерть за смерть " + i).getBytes());
      bobCiphertextMessages.add(bobCipher.encrypt(("смерть за смерть " + i).getBytes()));
    }

    seed = System.currentTimeMillis();

    Collections.shuffle(bobCiphertextMessages, new Random(seed));
    Collections.shuffle(bobPlaintextMessages, new Random(seed));

    for (int i=0;i<bobCiphertextMessages.size() / 2;i++) {
      byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages.get(i).serialize()));
      assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages.get(i)));
    }

    for (int i=aliceCiphertextMessages.size()/2;i<aliceCiphertextMessages.size();i++) {
      byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages.get(i).serialize()));
      assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages.get(i)));
    }

    for (int i=bobCiphertextMessages.size() / 2;i<bobCiphertextMessages.size(); i++) {
      byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages.get(i).serialize()));
      assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages.get(i)));
    }
  }

  private void initializeSessionsV3(SessionState aliceSessionState, SessionState bobSessionState)
      throws InvalidKeyException
  {
    ECKeyPair       aliceIdentityKeyPair = Curve.generateKeyPair();
    IdentityKeyPair aliceIdentityKey     = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                                                               aliceIdentityKeyPair.getPrivateKey());
    ECKeyPair       aliceBaseKey         = Curve.generateKeyPair();
    ECKeyPair       aliceEphemeralKey    = Curve.generateKeyPair();

    ECKeyPair alicePreKey = aliceBaseKey;

    ECKeyPair       bobIdentityKeyPair = Curve.generateKeyPair();
    IdentityKeyPair bobIdentityKey       = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                                                               bobIdentityKeyPair.getPrivateKey());
    ECKeyPair       bobBaseKey           = Curve.generateKeyPair();
    ECKeyPair       bobEphemeralKey      = bobBaseKey;

    ECKeyPair       bobPreKey            = Curve.generateKeyPair();

    AliceSignalProtocolParameters aliceParameters = AliceSignalProtocolParameters.newBuilder()
                                                                                 .setOurBaseKey(aliceBaseKey)
                                                                                 .setOurIdentityKey(aliceIdentityKey)
                                                                                 .setTheirOneTimePreKey(Optional.<ECPublicKey>absent())
                                                                                 .setTheirRatchetKey(bobEphemeralKey.getPublicKey())
                                                                                 .setTheirSignedPreKey(bobBaseKey.getPublicKey())
                                                                                 .setTheirIdentityKey(bobIdentityKey.getPublicKey())
                                                                                 .create();

    BobSignalProtocolParameters bobParameters = BobSignalProtocolParameters.newBuilder()
                                                                           .setOurRatchetKey(bobEphemeralKey)
                                                                           .setOurSignedPreKey(bobBaseKey)
                                                                           .setOurOneTimePreKey(Optional.<ECKeyPair>absent())
                                                                           .setOurIdentityKey(bobIdentityKey)
                                                                           .setTheirIdentityKey(aliceIdentityKey.getPublicKey())
                                                                           .setTheirBaseKey(aliceBaseKey.getPublicKey())
                                                                           .create();

    RatchetingSession.initializeSession(aliceSessionState, aliceParameters);
    RatchetingSession.initializeSession(bobSessionState, bobParameters);
  }

}
