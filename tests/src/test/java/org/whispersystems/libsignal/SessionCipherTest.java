package org.whispersystems.libsignal;

import junit.framework.TestCase;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.state.RDMStore;
import org.whispersystems.libsignal.state.impl.InMemoryRDMStore;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.ratchet.AliceSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.BobSignalProtocolParameters;
import org.whispersystems.libsignal.ratchet.RatchetingSession;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.util.Pair;
import org.whispersystems.libsignal.util.guava.Optional;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;


public class SessionCipherTest extends TestCase {


    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public void testRatchetDynamicMulticastSession() throws InvalidKeyException, DuplicateMessageException, IOException,
            LegacyMessageException, InvalidMessageException, NoSessionException, UntrustedIdentityException {
        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

        RDMStore aliceStore = new TestInMemoryRDMStore();
        RDMStore bobStore = new TestInMemoryRDMStore();

        SignalProtocolAddress bob_ad = new SignalProtocolAddress("+14159999999", 1);
        aliceStore.storeSession(bob_ad, aliceSessionRecord);
        bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

        SessionCipher aliceCipher = new SessionCipher(aliceStore, bob_ad);
        SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

        byte[] alicePlaintext = "Hello Bob !".getBytes();
        CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
        byte[] bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));

        assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));
        System.out.println(new String(bobPlaintext));

        byte[] bobReply = "Hi Alice !".getBytes();
        CiphertextMessage reply = bobCipher.encrypt(bobReply);
        byte[] receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));
        System.out.println(new String(receivedReply));
        assertTrue(Arrays.equals(bobReply, receivedReply));

        // Add new device
        RDMStore aliceStoreNewDevice = new TestInMemoryRDMStore();
        ArrayList<byte[]> messages = aliceStore.addjoin(aliceStoreNewDevice.getDevicePublicKey());
        // transfert du message depuis l'ancien vers le nouveau
        aliceStoreNewDevice.decJoin(messages);

        SessionRecord sessionRecord = new SessionRecord(aliceStore.loadSession(bob_ad).serialize());
        SessionState sessionState = sessionRecord.getSessionState();
        aliceCipher.half_ratchet(sessionState);
        aliceStore.storeSession(bob_ad, sessionRecord);
        aliceCipher = new SessionCipher(aliceStore, bob_ad);

        message = aliceCipher.encrypt(new byte[0]);
        SignalMessage ciphertext = new SignalMessage(message.serialize());
        bobCipher.decrypt(ciphertext);


        // TODO pour chaque session envoyer un msg enc au nouveau device
        byte[] msg = aliceStore.enc_add_join(bob_ad);
        aliceStoreNewDevice.dec_add_join(msg);


        // Test if bob reply can be read by both devices
        byte[] bobReplyB = "How are you ?".getBytes();
        CiphertextMessage replyB = bobCipher.encrypt(bobReplyB);
        byte[] rr = aliceCipher.decrypt(new SignalMessage(replyB.serialize()));

        SessionCipher aliceCipherNewDevice = new SessionCipher(aliceStoreNewDevice, bob_ad);
        byte[] rr_nd = aliceCipherNewDevice.decrypt(new SignalMessage(replyB.serialize()));

        System.out.println(new String(rr));
        System.out.println(new String(rr_nd));
        assertTrue(Arrays.equals(rr, rr_nd));

        //Alice envoie un message à Bob depuis son nouveau device

        message = aliceCipherNewDevice.encrypt("Fine, I test my new device".getBytes());
        bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));
        assertTrue(Arrays.equals(rr, rr_nd));
        System.out.println(new String(bobPlaintext));
        byte[] rdmEncMessage = aliceStoreNewDevice.enc(bob_ad, "Fine, I test my new device".getBytes());
        byte[] rdmReceivedMessage = aliceStore.dec(rdmEncMessage);
        System.out.println("message reçu par Alice1 " + new String(rdmReceivedMessage));


        //Alice envoie un second message à Bob depuis son nouveau device
        byte[] aliceNewDeviceReplyC = "I'm fine and you".getBytes();
        CiphertextMessage replyC = aliceCipherNewDevice.encrypt(aliceNewDeviceReplyC);
        byte[] readC = bobCipher.decrypt(new SignalMessage(replyC.serialize()));

        System.out.println("Ce que Bob à reçu :"+ new String(readC));

    }


    public void testRatchetDynamicMulticastSession2() throws InvalidKeyException, DuplicateMessageException, IOException,
            LegacyMessageException, InvalidMessageException, NoSessionException, UntrustedIdentityException {
        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

        RDMStore aliceStore = new TestInMemoryRDMStore();
        RDMStore bobStore = new TestInMemoryRDMStore();

        SignalProtocolAddress bob_ad = new SignalProtocolAddress("+14159999999", 1);
        aliceStore.storeSession(bob_ad, aliceSessionRecord);
        bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

        SessionCipher aliceCipher = new SessionCipher(aliceStore, bob_ad);
        SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

        byte[] alicePlaintext = "Hello Bob !".getBytes();
        CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
        byte[] bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));

        assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));
        System.out.println(new String(bobPlaintext));

        byte[] bobReply = "Hi Alice !".getBytes();
        CiphertextMessage reply = bobCipher.encrypt(bobReply);
        byte[] receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));
        System.out.println(new String(receivedReply));
        assertTrue(Arrays.equals(bobReply, receivedReply));

        // Add new device
        RDMStore aliceStoreNewDevice = new TestInMemoryRDMStore();
        ArrayList<byte[]> messages = aliceStore.addjoin(aliceStoreNewDevice.getDevicePublicKey());
        // transfert du message depuis l'ancien vers le nouveau
        aliceStoreNewDevice.decJoin(messages);

        SessionRecord sessionRecord = new SessionRecord(aliceStore.loadSession(bob_ad).serialize());
        SessionState sessionState = sessionRecord.getSessionState();
        aliceCipher.half_ratchet(sessionState);
        aliceStore.storeSession(bob_ad, sessionRecord);
        aliceCipher = new SessionCipher(aliceStore, bob_ad);

        message = aliceCipher.encrypt(new byte[0]);
        SignalMessage ciphertext = new SignalMessage(message.serialize());
        bobCipher.decrypt(ciphertext);


        message = aliceCipher.encrypt("Test second message".getBytes());
        ciphertext = new SignalMessage(message.serialize());
        byte[] decrypt = bobCipher.decrypt(ciphertext);
        System.out.println(new String(decrypt));


        // TODO pour chaque session envoyer un msg enc au nouveau device
        byte[] msg = aliceStore.enc_add_join(bob_ad);
        aliceStoreNewDevice.dec_add_join(msg);


        // Test if bob reply can be read by both devices
        byte[] bobReplyB = "How are you ?".getBytes();
        CiphertextMessage replyB = bobCipher.encrypt(bobReplyB);
        byte[] rr = aliceCipher.decrypt(new SignalMessage(replyB.serialize()));

        SessionCipher aliceCipherNewDevice = new SessionCipher(aliceStoreNewDevice, bob_ad);
        byte[] rr_nd = aliceCipherNewDevice.decrypt(new SignalMessage(replyB.serialize()));

        System.out.println(new String(rr));
        System.out.println(new String(rr_nd));
        assertTrue(Arrays.equals(rr, rr_nd));

        message = aliceCipherNewDevice.encrypt("Fine, I test my new device".getBytes());
        bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));
        assertTrue(Arrays.equals(rr, rr_nd));
        System.out.println(new String(bobPlaintext));


        //Alice envoie un message à Bob depuis son nouveau device
        byte[] aliceNewDeviceReplyC = "I'm fine and you".getBytes();
        CiphertextMessage replyC = aliceCipherNewDevice.encrypt(aliceNewDeviceReplyC);
        byte[] readC = bobCipher.decrypt(new SignalMessage(replyC.serialize()));

        System.out.println("Ce que Bob à reçu :"+ new String(readC));

    }

    public void testRatchetDynamicMulticastSession3devices()
            throws InvalidKeyException, DuplicateMessageException,
            LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException, InvalidKeySpecException, IOException {
        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

        RDMStore aliceStore = new TestInMemoryRDMStore();
        RDMStore bobStore = new TestInMemoryRDMStore();

        SignalProtocolAddress bob_ad = new SignalProtocolAddress("+14159999999", 1);
        SignalProtocolAddress alice_ad = new SignalProtocolAddress("+14158888888", 1);

        aliceStore.storeSession(bob_ad, aliceSessionRecord);
        bobStore.storeSession(alice_ad, bobSessionRecord);

        SessionCipher aliceCipher = new SessionCipher(aliceStore, bob_ad);
        SessionCipher bobCipher = new SessionCipher(bobStore, alice_ad);

        //1. Alice envoie un message, Bob répond
        byte[] alicePlaintext = "Hello Bob !".getBytes();
        CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
        byte[] bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));
        assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));
        System.out.println(new String(bobPlaintext));

        byte[] bobReply = "Hi Alice !".getBytes();
        CiphertextMessage reply = bobCipher.encrypt(bobReply);
        byte[] receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));
        System.out.println(new String(receivedReply));
        assertTrue(Arrays.equals(bobReply, receivedReply));

        RDMStore aliceStoreNewDevice = new TestInMemoryRDMStore();

        //2. ajout du nouveau device
        ArrayList<byte[]> messages = aliceStore.addjoin(aliceStoreNewDevice.getDevicePublicKey());
        aliceStoreNewDevice.decJoin(messages);

        // Run half-ratchet
        SessionRecord sr = aliceStore.loadSession(bob_ad);
        SessionRecord sessionRecord = new SessionRecord(sr.serialize());
        SessionState sessionState = sessionRecord.getSessionState();
        aliceCipher.half_ratchet(sessionState);
        message = aliceCipher.encrypt(new byte[0]);
        bobCipher.decrypt(new SignalMessage(message.serialize()));
        // NB pour chaque session il faut envoyer un msg enc_add_join a chaque device
        byte[] msg = aliceStore.enc_add_join(bob_ad);
        aliceStoreNewDevice.dec_add_join(msg);

        //3. Test if bob reply can be read by both devices
        byte[] bobReplyB = "How are you ?".getBytes();
        CiphertextMessage replyB = bobCipher.encrypt(bobReplyB);
        byte[] rr = aliceCipher.decrypt(new SignalMessage(replyB.serialize()));
        SessionCipher aliceCipherNewDevice = new SessionCipher(aliceStoreNewDevice, bob_ad);
        byte[] rr_nd = aliceCipherNewDevice.decrypt(new SignalMessage(replyB.serialize()));
        System.out.println(new String(rr));
        System.out.println(new String(rr_nd));

        //4.Alice envoie un message à Bob depuis son nouveau device
        byte[] aliceNewDeviceReplyC = "Fine, I test my new device".getBytes();
        CiphertextMessage replyC = aliceCipherNewDevice.encrypt(aliceNewDeviceReplyC);
        //alice new device envoie le RDM message à l'ancien device
        msg =  aliceStoreNewDevice.enc(bob_ad, aliceNewDeviceReplyC);
        byte[] rec_msg = aliceStore.dec(msg);

        System.out.println("recu par l'ancien device: "+ new String(rec_msg));
        //Bob recoit le message
        byte[] readC = bobCipher.decrypt(new SignalMessage(replyC.serialize()));
        System.out.println("Ce que Bob à reçu :"+ new String(readC));

        //5. Bob répond
        byte[] bobReplyC = "How are you Alice ?".getBytes();
        CiphertextMessage bobreplyC = bobCipher.encrypt(bobReplyC);
        System.out.println(" received by new device from bob :" + new String(aliceCipherNewDevice.decrypt(new SignalMessage(bobreplyC.serialize()))));
        System.out.println(" received by first device from bob :" + new String(aliceCipher.decrypt(new SignalMessage(bobreplyC.serialize()))));

        //6. Test d'un troisième device d'Alice
        RDMStore aliceStoreNewDevice2 = new TestInMemoryRDMStore();
        // ajout du nouveau device
        messages = aliceStore.addjoin(aliceStoreNewDevice2.getDevicePublicKey());
        aliceStoreNewDevice2.decJoin(messages);
        aliceStoreNewDevice.decAdd(messages);
        // Run half-ratchet
        sr = aliceStore.loadSession(bob_ad);
        sessionRecord = new SessionRecord(sr.serialize());
        sessionState = sessionRecord.getSessionState();
        aliceCipher.half_ratchet(sessionState);
        message = aliceCipher.encrypt(new byte[0]);
        bobCipher.decrypt(new SignalMessage(message.serialize()));
        msg = aliceStore.enc_add_join(bob_ad);
        aliceStoreNewDevice2.dec_add_join(msg);
        aliceStoreNewDevice.dec_add_join(msg);

        //7. test si le troisieme device peut envoyer un message
        SessionCipher aliceCipherNewDevice2 = new SessionCipher(aliceStoreNewDevice2, bob_ad);
        byte[] aliceNewDeviceReplyD = "Fine, I test my new device 3".getBytes();
        CiphertextMessage replyD = aliceCipherNewDevice2.encrypt(aliceNewDeviceReplyD);
        msg =  aliceStoreNewDevice2.enc(bob_ad, aliceNewDeviceReplyD);
        //les autres devices et Bob recçoivent
        byte[] rec_msgD_1 = aliceStore.dec(msg);
        byte[] rec_msgD_2 = aliceStoreNewDevice.dec(msg);
        System.out.println("index de chain key après dec = "+ aliceStore.loadSession(bob_ad).getSessionState().getSenderChainKey().getIndex());

        System.out.println("recu par l'ancien device: "+ new String(rec_msgD_1));
        System.out.println("recu par l'ancien new device: "+ new String(rec_msgD_2));
        byte[] readD = bobCipher.decrypt(new SignalMessage(replyD.serialize()));
        System.out.println("Ce que Bob à reçu :"+ new String(readD));

        //8. Le troisième device renvoie un message
        byte[] aliceNewDeviceReplyE = "and it seems it works fine".getBytes();
        CiphertextMessage replyE = aliceCipherNewDevice2.encrypt(aliceNewDeviceReplyE);
        //les autres devices et Bob recçoivent
        msg =  aliceStoreNewDevice2.enc(bob_ad, aliceNewDeviceReplyE);
        System.out.println("INDEX entree de dec : " + aliceStore.loadSession(bob_ad).getSessionState().getSenderChainKey().getIndex());
        byte[] rec_msgE_1 = aliceStore.dec(msg);
        System.out.println("INDEX sortie de dec : " + aliceStore.loadSession(bob_ad).getSessionState().getSenderChainKey().getIndex());
        byte[] rec_msgE_2 = aliceStoreNewDevice.dec(msg);
        System.out.println("recu par l'ancien device: "+ new String(rec_msgE_1));
        System.out.println("recu par l'ancien new device: "+ new String(rec_msgE_2));
        byte[] readE = bobCipher.decrypt(new SignalMessage(replyE.serialize()));
        System.out.println("Ce que Bob à reçu :"+ new String(readE));

        //9. Le premier device envoie un message
        byte[] aliceReplyF = "so how do you do?".getBytes();
        CiphertextMessage replyF = aliceCipher.encrypt(aliceReplyF);
        //les autres devices et Bob recçoivent
        msg =  aliceStore.enc(bob_ad, aliceReplyF);
        byte[] rec_msgF_1 = aliceStoreNewDevice.dec(msg);
        byte[] rec_msgF_2 = aliceStoreNewDevice2.dec(msg);
        System.out.println("recu par new device: "+ new String(rec_msgF_1));
        System.out.println("recu par new device2: "+ new String(rec_msgF_2));
        byte[] readF = bobCipher.decrypt(new SignalMessage(replyF.serialize()));
        System.out.println("Ce que Bob à reçu :"+ new String(readF));

    }


    public void testRatchetDynamicMulticastSession3devices10000Messages()
            throws InvalidKeyException, DuplicateMessageException,
            LegacyMessageException, InvalidMessageException, NoSessionException, UntrustedIdentityException, InvalidKeySpecException, IOException {
        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

        RDMStore aliceStore = new TestInMemoryRDMStore();
        RDMStore bobStore = new TestInMemoryRDMStore();

        SignalProtocolAddress bob_ad = new SignalProtocolAddress("+14159999999", 1);
        aliceStore.storeSession(bob_ad, aliceSessionRecord);
        bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

        SessionCipher aliceCipher = new SessionCipher(aliceStore, bob_ad);
        SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

        byte[] alicePlaintext = "Hello Bob !".getBytes();
        CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
        byte[] bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));

        assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));
        System.out.println(new String(bobPlaintext));

        byte[] bobReply = "Hi Alice !".getBytes();
        CiphertextMessage reply = bobCipher.encrypt(bobReply);
        byte[] receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));

        System.out.println(new String(receivedReply));

        assertTrue(Arrays.equals(bobReply, receivedReply));

        RDMStore aliceStoreNewDevice = new TestInMemoryRDMStore();

        // ajout du nouveau device

        ArrayList<byte[]> messages = aliceStore.addjoin(aliceStoreNewDevice.getDevicePublicKey());
        aliceStoreNewDevice.decJoin(messages);

        // Run half-ratchet
        SessionRecord sr = aliceStore.loadSession(bob_ad);
        SessionRecord sessionRecord = new SessionRecord(sr.serialize());
        SessionState sessionState = sessionRecord.getSessionState();
        aliceCipher.half_ratchet(sessionState);
        message = aliceCipher.encrypt(new byte[0]);
        bobCipher.decrypt(new SignalMessage(message.serialize()));


        // NB pour chaque session il faut envoyer un msg enc_add_join a chaque device
        byte[] msg = aliceStore.enc_add_join(bob_ad);
        aliceStoreNewDevice.dec_add_join(msg);

        // Test if bob reply can be read by both devices
        byte[] bobReplyB = "How are you ?".getBytes();
        CiphertextMessage replyB = bobCipher.encrypt(bobReplyB);
        byte[] rr = aliceCipher.decrypt(new SignalMessage(replyB.serialize()));

        SessionCipher aliceCipherNewDevice = new SessionCipher(aliceStoreNewDevice, bob_ad);
        byte[] rr_nd = aliceCipherNewDevice.decrypt(new SignalMessage(replyB.serialize()));

        System.out.println(new String(rr));
        System.out.println(new String(rr_nd));

        //Alice envoie un message à Bob depuis son nouveau device
        byte[] aliceNewDeviceReplyC = "Fine, I test my new device".getBytes();
        CiphertextMessage replyC = aliceCipherNewDevice.encrypt(aliceNewDeviceReplyC);

        //alice new device envoie le RDM message à l'ancien device
        msg =  aliceStoreNewDevice.enc(bob_ad, aliceNewDeviceReplyC);
        byte[] rec_msg = aliceStore.dec(msg);
        System.out.println("recu par l'ancien device: "+ new String(rec_msg));

        byte[] readC = bobCipher.decrypt(new SignalMessage(replyC.serialize()));
        System.out.println("Ce que Bob à reçu :"+ new String(readC));
        //
        byte[] bobReplyC = "How are you Alice ?".getBytes();
        CiphertextMessage bobreplyC = bobCipher.encrypt(bobReplyC);
        System.out.println(" received by new device from bob :" + new String(aliceCipherNewDevice.decrypt(new SignalMessage(bobreplyC.serialize()))));
        System.out.println(" received by first device from bob :" + new String(aliceCipher.decrypt(new SignalMessage(bobreplyC.serialize()))));

        // Test d'un troisième device d'Alice
        RDMStore aliceStoreNewDevice2 = new TestInMemoryRDMStore();

        // ajout du nouveau device
        messages = aliceStore.addjoin(aliceStoreNewDevice2.getDevicePublicKey());
        aliceStoreNewDevice2.decJoin(messages);
        aliceStoreNewDevice.decAdd(messages);
        // Run half-ratchet
        sr = aliceStore.loadSession(bob_ad);
        sessionRecord = new SessionRecord(sr.serialize());
        sessionState = sessionRecord.getSessionState();
        aliceCipher.half_ratchet(sessionState);
        message = aliceCipher.encrypt(new byte[0]);
        bobCipher.decrypt(new SignalMessage(message.serialize()));


        // TODO pour chaque session envoyer un msg enc au nouveau device
        msg = aliceStore.enc_add_join(bob_ad);
        aliceStoreNewDevice2.dec_add_join(msg);
        System.out.println("sort du enc_add_join pour AliceNewDevice2");
        aliceStoreNewDevice.dec_add_join(msg);
        System.out.println("sort du enc_add_join pour AliceNewDevice");

        // test si le troisieme device peut envoyer un message
        SessionCipher aliceCipherNewDevice2 = new SessionCipher(aliceStoreNewDevice2, bob_ad);
        byte[] aliceNewDeviceReplyD = "Fine, I test my new device 3".getBytes();
        CiphertextMessage replyD = aliceCipherNewDevice2.encrypt(aliceNewDeviceReplyD);

        msg =  aliceStoreNewDevice2.enc(bob_ad, aliceNewDeviceReplyD);
        byte[] rec_msg_1 = aliceStore.dec(msg);
        byte[] rec_msg_2 = aliceStoreNewDevice.dec(msg);
        System.out.println("recu par l'ancien device: "+ new String(rec_msg_1));
        System.out.println("recu par l'ancien new device: "+ new String(rec_msg_2));


        byte[] readD = bobCipher.decrypt(new SignalMessage(replyD.serialize()));
        System.out.println("Ce que Bob à reçu :"+ new String(readD));


        Pair<SessionCipher, RDMStore> d1 = new Pair<>(aliceCipher, aliceStore);
        Pair<SessionCipher, RDMStore> d2 = new Pair<>(aliceCipherNewDevice, aliceStoreNewDevice);
        Pair<SessionCipher, RDMStore> d3 = new Pair<>(aliceCipherNewDevice2, aliceStoreNewDevice2);
        List<Pair<SessionCipher, RDMStore>> devices = Arrays.asList(d1, d2, d3);
        for(int i = 0; i < 10000; i++){
            String uuid = UUID.randomUUID().toString();
            Random rand = new Random();
            int index = rand.nextInt(devices.size());
            SessionCipher randomAliceCipher = devices.get(index).first();
            RDMStore randomAliceStore = devices.get(index).second();
            msg = uuid.getBytes();
            System.out.println("using alice cipher "+ index + " - message: " + i + " : " + uuid);
            reply = randomAliceCipher.encrypt(msg);
            byte[] enc = randomAliceStore.enc(bob_ad, msg);
            for(int j = 0; j < devices.size(); j++){
                if (j != index) {
                    devices.get(j).second().dec(enc);
                }
            }

            byte[] read = bobCipher.decrypt(new SignalMessage(reply.serialize()));
            assertTrue(Arrays.equals(msg, read));
            String s = new String(read) + i;
            CiphertextMessage bobreply = bobCipher.encrypt(s.getBytes());

            for(int j = 0; j < devices.size(); j++){
                SessionCipher cipher = devices.get(j).first();
                byte[] ans = cipher.decrypt(new SignalMessage(bobreply.serialize()));
                System.out.println(j + " " + new String(ans) );
                assertTrue(Arrays.equals(s.getBytes(), ans));
            }
        }
    }



    public void testBasicSessionV3()
            throws InvalidKeyException, DuplicateMessageException,
            LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException {
        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());
        runInteraction(aliceSessionRecord, bobSessionRecord);
    }

    public void testMessageKeyLimits() throws Exception {
        SessionRecord aliceSessionRecord = new SessionRecord();
        SessionRecord bobSessionRecord = new SessionRecord();

        initializeSessionsV3(aliceSessionRecord.getSessionState(), bobSessionRecord.getSessionState());

        RDMStore aliceStore = new TestInMemoryRDMStore();
        RDMStore bobStore = new TestInMemoryRDMStore();

        aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
        bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

        SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
        SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

        List<CiphertextMessage> inflight = new LinkedList<>();

        for (int i = 0; i < 2010; i++) {
            inflight.add(aliceCipher.encrypt("you've never been so hungry, you've never been so cold".getBytes()));
        }

        bobCipher.decrypt(new SignalMessage(inflight.get(1000).serialize()));
        bobCipher.decrypt(new SignalMessage(inflight.get(inflight.size() - 1).serialize()));

        try {
            bobCipher.decrypt(new SignalMessage(inflight.get(0).serialize()));
            throw new AssertionError("Should have failed!");
        } catch (DuplicateMessageException dme) {
            // good
        }
    }

    private void runInteraction(SessionRecord aliceSessionRecord, SessionRecord bobSessionRecord)
            throws DuplicateMessageException, LegacyMessageException, InvalidMessageException, NoSuchAlgorithmException, NoSessionException, UntrustedIdentityException {
        RDMStore aliceStore = new TestInMemoryRDMStore();
        RDMStore bobStore = new TestInMemoryRDMStore();

        aliceStore.storeSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
        bobStore.storeSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

        SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
        SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

        byte[] alicePlaintext = "This is a plaintext message.".getBytes();
        CiphertextMessage message = aliceCipher.encrypt(alicePlaintext);
        byte[] bobPlaintext = bobCipher.decrypt(new SignalMessage(message.serialize()));

        assertTrue(Arrays.equals(alicePlaintext, bobPlaintext));

        byte[] bobReply = "This is a message from Bob.".getBytes();
        CiphertextMessage reply = bobCipher.encrypt(bobReply);
        byte[] receivedReply = aliceCipher.decrypt(new SignalMessage(reply.serialize()));

        assertTrue(Arrays.equals(bobReply, receivedReply));

        List<CiphertextMessage> aliceCiphertextMessages = new ArrayList<>();
        List<byte[]> alicePlaintextMessages = new ArrayList<>();

        for (int i = 0; i < 50; i++) {
            alicePlaintextMessages.add(("смерть за смерть " + i).getBytes());
            aliceCiphertextMessages.add(aliceCipher.encrypt(("смерть за смерть " + i).getBytes()));
        }

        long seed = System.currentTimeMillis();

        Collections.shuffle(aliceCiphertextMessages, new Random(seed));
        Collections.shuffle(alicePlaintextMessages, new Random(seed));

        for (int i = 0; i < aliceCiphertextMessages.size() / 2; i++) {
            byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages.get(i).serialize()));
            assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages.get(i)));
        }

        List<CiphertextMessage> bobCiphertextMessages = new ArrayList<>();
        List<byte[]> bobPlaintextMessages = new ArrayList<>();

        for (int i = 0; i < 20; i++) {
            bobPlaintextMessages.add(("смерть за смерть " + i).getBytes());
            bobCiphertextMessages.add(bobCipher.encrypt(("смерть за смерть " + i).getBytes()));
        }

        seed = System.currentTimeMillis();

        Collections.shuffle(bobCiphertextMessages, new Random(seed));
        Collections.shuffle(bobPlaintextMessages, new Random(seed));

        for (int i = 0; i < bobCiphertextMessages.size() / 2; i++) {
            byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages.get(i).serialize()));
            assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages.get(i)));
        }

        for (int i = aliceCiphertextMessages.size() / 2; i < aliceCiphertextMessages.size(); i++) {
            byte[] receivedPlaintext = bobCipher.decrypt(new SignalMessage(aliceCiphertextMessages.get(i).serialize()));
            assertTrue(Arrays.equals(receivedPlaintext, alicePlaintextMessages.get(i)));
        }

        for (int i = bobCiphertextMessages.size() / 2; i < bobCiphertextMessages.size(); i++) {
            byte[] receivedPlaintext = aliceCipher.decrypt(new SignalMessage(bobCiphertextMessages.get(i).serialize()));
            assertTrue(Arrays.equals(receivedPlaintext, bobPlaintextMessages.get(i)));
        }
    }

    private void initializeSessionsV3(SessionState aliceSessionState, SessionState bobSessionState)
            throws InvalidKeyException {
        ECKeyPair aliceIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.getPublicKey()),
                aliceIdentityKeyPair.getPrivateKey());
        ECKeyPair aliceBaseKey = Curve.generateKeyPair();
        ECKeyPair aliceEphemeralKey = Curve.generateKeyPair();

        ECKeyPair alicePreKey = aliceBaseKey;

        ECKeyPair bobIdentityKeyPair = Curve.generateKeyPair();
        IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.getPublicKey()),
                bobIdentityKeyPair.getPrivateKey());
        ECKeyPair bobBaseKey = Curve.generateKeyPair();
        ECKeyPair bobEphemeralKey = bobBaseKey;

        ECKeyPair bobPreKey = Curve.generateKeyPair();

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
