package org.whispersystems.libsignal.state.impl;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.SignalProtos;
import org.whispersystems.libsignal.ratchet.ChainKey;
import org.whispersystems.libsignal.ratchet.RootKey;
import org.whispersystems.libsignal.state.*;
import org.whispersystems.libsignal.util.Pair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class InMemoryRDMStore extends InMemorySignalProtocolStore implements RDMStore{

    public InMemoryRDMStore(IdentityKeyPair generateIdentityKeyPair, int generateRegistrationId) {
        super(generateIdentityKeyPair, generateRegistrationId);
    }

    public byte[] join(PublicKey newDevicePublicKey) {
        SignalProtos.RatchetedDynamicMulticastMessage msg;
        byte[] dump = dumpSessions(true);
        byte[] wrap = new byte[0];
        byte[] cipherJoin = new byte[0];
        try {
            Cipher cipher = null;
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, newDevicePublicKey);
            SecretKey aes = KeyGenerator.getInstance("AES").generateKey();
            wrap = cipher.doFinal(aes.getEncoded());

            cipher = Cipher.getInstance("AES");  //FIXME use AES/ECB/PKCS5Padding ?
            cipher.init(Cipher.ENCRYPT_MODE, aes);
            cipherJoin = cipher.doFinal(dump);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
        }

        msg = SignalProtos.RatchetedDynamicMulticastMessage.newBuilder()
                .addWrap(ByteString.copyFrom(wrap))
                .setAction(SignalProtos.RatchetedDynamicMulticastMessage.Action.JOIN)
                .setCipher(ByteString.copyFrom(cipherJoin)).build(); //FIXME replace copyfrom ?
        return msg.toByteArray();

    }


    public void decJoin(ArrayList<byte[]> messages) {
        for (byte[] m : messages) {
            decJoin(m);
        }
    }

    public void decJoin(byte[] m) {
        SignalProtos.RatchetedDynamicMulticastMessage msg = null;
        try {
            msg = SignalProtos.RatchetedDynamicMulticastMessage.parseFrom(m);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
            return;
        }

        if (msg.getAction() == SignalProtos.RatchetedDynamicMulticastMessage.Action.JOIN) {
            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, getDevicePrivateKey());
                byte[] encodedKey = new byte[0];

                for (ByteString wrap : msg.getWrapList()) {
                    encodedKey = cipher.doFinal(wrap.toByteArray());
                    if (encodedKey.length == 0) {
                        continue;
                    }
                }
                SecretKey aes = new SecretKeySpec(encodedKey, "AES");

                cipher = Cipher.getInstance("AES"); //FIXME use AES/ECB/PKCS5Padding ?
                cipher.init(Cipher.DECRYPT_MODE, aes);
                byte[] dump = cipher.doFinal(msg.getCipher().toByteArray());
                load(dump);
                setOwnEphemeralKeys(getDevicePrivateKey(), getDevicePublicKey());
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
                e.printStackTrace();
            }

        }
    }


    public byte[] enc_add_join(SignalProtocolAddress ad) {
        try {
            SessionRecord sr = loadSession(ad);
            SessionRecord sessionRecord = new SessionRecord(sr.serialize());
            EphemaralUpdater ephemaralUpdater = new EphemaralUpdater(ad, sessionRecord).invoke();
            byte[] newMacKey = ephemaralUpdater.getNewMacKey();
            List<ByteString> allEphemeralPublicKeyList = ephemaralUpdater.getAllEphemeralPublicKeyList();
            byte[] tag = ephemaralUpdater.getTag();


            // build enc_add_join_msg
            //ajout celine
            sessionRecord.signalFilterAllStates();
            //fin ajout Céline
            StorageProtos.RatchetDynamicMulticastMessageEncAddJoinStructure enc_add_join_msg;
            enc_add_join_msg = StorageProtos.RatchetDynamicMulticastMessageEncAddJoinStructure.newBuilder()
                    .setSession(ByteString.copyFrom(sessionRecord.serialize()))
                    .setOwnIdentityKeyPair(ByteString.copyFrom(getIdentityKeyPair().serialize()))
                    .setTheirIdentityKeyPair(ByteString.copyFrom(getIdentity(ad).serialize()))
                    .addAllSignedPrekey(dumpSignedPreKey())
                    .addAllAllDevicePublicKey(getDevicesPublicKeys())
                    .build();


            // build RDM enc message
     //       sessionRecord.signalFilterAllStates();
            StorageProtos.RatchetDynamicMulticastEncStructure rdmm;
            rdmm = StorageProtos.RatchetDynamicMulticastEncStructure.newBuilder()
                    .setJoinMessage(enc_add_join_msg)
                    .setMacKey(ByteString.copyFrom(newMacKey))
                    .setTag(ByteString.copyFrom(tag))
                    .build();

            // wrap aes with all rsa pub key
            SecretKey aeskey = KeyGenerator.getInstance("AES").generateKey();
            List<ByteString> aes_wrap = getAESWrapList(sr, aeskey);
            // cipher rdm message
            Cipher cipher = Cipher.getInstance("AES");  //FIXME use AES/ECB/PKCS5Padding ?
            cipher.init(Cipher.ENCRYPT_MODE, aeskey);
            byte[] cipher_rdm = cipher.doFinal(rdmm.toByteArray());
            SignalProtos.RatchetedDynamicMulticastMessage msg;
            msg = SignalProtos.RatchetedDynamicMulticastMessage.newBuilder().setCipher(ByteString.copyFrom(cipher_rdm))
                    .setName(ad.getName())
                    .setAction(SignalProtos.RatchetedDynamicMulticastMessage.Action.ENC_JOIN)
                    .addAllWrap(aes_wrap)
                    .addAllPublicKey(allEphemeralPublicKeyList)
                    .build();

            return msg.toByteArray();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | InvalidKeySpecException | IllegalBlockSizeException e1) {
            e1.printStackTrace();
        }

        return new byte[0];
    }

    private List<ByteString> getAESWrapList(SessionRecord sr, SecretKey aeskey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        List<ByteString> aes_wrap = new ArrayList<ByteString>();
        for (ByteString e : sr.getSessionState().getAllEphemeralPublicKey()) {
            X509EncodedKeySpec ePubKeySpec = new X509EncodedKeySpec(e.toByteArray());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey rsa_key = keyFactory.generatePublic(ePubKeySpec);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, rsa_key);
            byte[] wrap = cipher.doFinal(aeskey.getEncoded());
            aes_wrap.add(ByteString.copyFrom(wrap));
        }
        return aes_wrap;
    }


    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    public void dec_add_join(byte[] m) {
        SignalProtos.RatchetedDynamicMulticastMessage msg = null;
        try {
            msg = SignalProtos.RatchetedDynamicMulticastMessage.parseFrom(m);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
            return;
        }
        System.out.println(msg.getName());
        SignalProtocolAddress ad = new SignalProtocolAddress(msg.getName(), 1);
        if (msg.getAction() == SignalProtos.RatchetedDynamicMulticastMessage.Action.ENC_JOIN) {
            try {
                SessionRecord currentSessionRecord = loadSession(ad);
                byte[] bytes = decrypt(msg, currentSessionRecord);
                StorageProtos.RatchetDynamicMulticastEncStructure rdmenc;
                rdmenc = StorageProtos.RatchetDynamicMulticastEncStructure.parseFrom(bytes);
                SessionRecord sessionRecord = new SessionRecord(rdmenc.getJoinMessage().getSession().toByteArray());
                List<ByteString> allEphemeralPublicKey = msg.getPublicKeyList();
                byte[] tag = rdmenc.getTag().toByteArray();
                ByteString new_mac_key = rdmenc.getMacKey();
                verifyMac(msg, currentSessionRecord, tag, new_mac_key);

                //ajoutCeline
                StorageProtos.SessionStructure.RatchetDynamicMulticastStructure rdms;
                rdms = currentSessionRecord.getSessionState().getStructure().getRatchetDynamicMulticastStructure();
                sessionRecord.getSessionState().setRatchetDynamicMulticastStructure(rdms);
                //fin ajout

                storeSession(ad, sessionRecord);
                // setup own identity key
                ByteString ownIdentityKeyPair = rdmenc.getJoinMessage().getOwnIdentityKeyPair();
                StorageProtos.IdentityKeyPairStructure identityKeyPairStructure = StorageProtos.IdentityKeyPairStructure.parseFrom(ownIdentityKeyPair);
                IdentityKey publicKey = new IdentityKey(Curve.decodePoint(identityKeyPairStructure.getPublicKey().toByteArray(), 0));
                ECPrivateKey privateKey = Curve.decodePrivatePoint(identityKeyPairStructure.getPrivateKey().toByteArray());
                setIdentityKeyPair(new IdentityKeyPair(publicKey, privateKey));
                // setup presigned keys + identity keys
                ByteString theirIdentityKeyPair = rdmenc.getJoinMessage().getTheirIdentityKeyPair();
                ECPublicKey ecPublicKey = Curve.decodePoint(theirIdentityKeyPair.toByteArray(), 0);
                saveIdentity(ad, new IdentityKey(ecPublicKey));

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidKeySpecException | IOException | BadPaddingException | org.whispersystems.libsignal.InvalidKeyException e) {
                e.printStackTrace();
            }
        }
    }

    public byte[] add(SignalProtocolAddress ad, List<ByteString> allEphemeralPublicKeys) {
        try {
            SessionRecord sessionRecord = loadSession(ad);
            byte[] newMacKey = KeyGenerator.getInstance("HmacSHA256").generateKey().getEncoded();
            byte[] preMacKey = sessionRecord.getSessionState().getMacKey();

            //create tag
            Mac sha256_HMAC = null;
            sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec practicalMacKey = new SecretKeySpec(preMacKey, "HmacSHA256");
            sha256_HMAC.init(practicalMacKey);
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            data.write(newMacKey);
           // for (Iterator<ByteString> i = sessionRecord.getSessionState().getAllEphemeralPublicKey().iterator(); i.hasNext(); ) {
            for (Iterator<ByteString> i = allEphemeralPublicKeys.iterator(); i.hasNext(); ) {
                ByteString item = i.next();
                data.write(item.toByteArray());
            }
            byte[] tag = sha256_HMAC.doFinal(data.toByteArray());

            // Record new MacKey in Session State
            StorageProtos.SessionStructure.RatchetDynamicMulticastStructure rdms;
            rdms = sessionRecord.getSessionState().getStructure().getRatchetDynamicMulticastStructure();
            StorageProtos.SessionStructure.RatchetDynamicMulticastStructure new_rmds;
            new_rmds = rdms.toBuilder().setMacKey(ByteString.copyFrom(newMacKey)).build();
            sessionRecord.getSessionState().setRatchetDynamicMulticastStructure(new_rmds);
            storeSession(ad, sessionRecord);


            //Build RDM add message
            StorageProtos.RatchetDynamicMulticastAddStructure.Builder builder = StorageProtos.RatchetDynamicMulticastAddStructure.newBuilder();
            StorageProtos.RatchetDynamicMulticastAddStructure rdmm = builder.setTag(ByteString.copyFrom(tag))
                    .setMacKey(ByteString.copyFrom(newMacKey))
                    .build();

            //Encrypts RDM add message
            // wrap aes with all rsa pub key
            SecretKey aeskey = KeyGenerator.getInstance("AES").generateKey();
            List<ByteString> aes_wrap = getAESWrapList(sessionRecord, aeskey);
            // cipher rdm message
            Cipher cipher = Cipher.getInstance("AES");  //FIXME use AES/ECB/PKCS5Padding ?
            cipher.init(Cipher.ENCRYPT_MODE, aeskey);
            byte[] cipher_rdm = cipher.doFinal(rdmm.toByteArray());
            SignalProtos.RatchetedDynamicMulticastMessage msg;
            msg = SignalProtos.RatchetedDynamicMulticastMessage.newBuilder()
                    .setCipher(ByteString.copyFrom(cipher_rdm))
                    .setName(ad.getName())
                    .addAllPublicKey(allEphemeralPublicKeys)
                    .addAllWrap(aes_wrap)
                    .setAction(SignalProtos.RatchetedDynamicMulticastMessage.Action.ADD)
                    //.addRDMEncryptedAddStructure(ByteString.copyFrom(cipherRDMadd))
                    .build();
            return msg.toByteArray();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | InvalidKeySpecException | IllegalBlockSizeException e1) {
            e1.printStackTrace();
        }
        return new byte[0];
    }


    /*
     *@param SIgnalProtocolAdress ad to know which session is concerned (to load the session record)
     * param SignalProtocolStore the device "Signal account"
     * param String text the message
     */
    public byte[] enc(SignalProtocolAddress ad, byte[] text) {
        try {
            SessionRecord sr = loadSession(ad);
            SessionRecord sessionRecord = new SessionRecord(sr.serialize());
            EphemaralUpdater ephemaralUpdater = new EphemaralUpdater(ad, sessionRecord).invoke();
            byte[] newMacKey = ephemaralUpdater.getNewMacKey();
            List<ByteString> allEphemeralPublicKeyList = ephemaralUpdater.getAllEphemeralPublicKeyList();
            byte[] tag = ephemaralUpdater.getTag();

            // build message
            StorageProtos.RatchetDynamicMulticastMessageStructure txtmsg = StorageProtos.RatchetDynamicMulticastMessageStructure.newBuilder()
                    .setText(ByteString.copyFrom(text))
                    .setSecretRatchetKey(ByteString.copyFrom(sr.getSessionState().getLatestRatchetKeyPrivate()))
                    .setPublicRatchetKey(ByteString.copyFrom(sr.getSessionState().getLatestRatchetKeyPublic()))//FIXME envoyer keyPair plutot private public.
                    .build();

            // build RDM enc message
            sessionRecord.signalFilterAllStates();
            StorageProtos.RatchetDynamicMulticastEncStructure rdmenc;
            rdmenc = StorageProtos.RatchetDynamicMulticastEncStructure.newBuilder()
                    .setMessage(txtmsg)
                    .setMacKey(ByteString.copyFrom(newMacKey))
                    .setTag(ByteString.copyFrom(tag))
                    .build();

            // wrap aes with all rsa pub key
            SecretKey aes = KeyGenerator.getInstance("AES").generateKey();
            List<ByteString> aes_wrap = getAESWrapList(sr, aes);
            // cipher rdm enc message
            Cipher cipher = Cipher.getInstance("AES");  //FIXME use AES/ECB/PKCS5Padding ?
            cipher.init(Cipher.ENCRYPT_MODE, aes);
            byte[] cipherRDMEnc = cipher.doFinal(rdmenc.toByteArray());

            //build the final RDM message
            SignalProtos.RatchetedDynamicMulticastMessage msg;
            msg = SignalProtos.RatchetedDynamicMulticastMessage.newBuilder().setCipher(ByteString.copyFrom(cipherRDMEnc))
                    .setName(ad.getName())
                    .setAction(SignalProtos.RatchetedDynamicMulticastMessage.Action.ENC)
                    .addAllWrap(aes_wrap)
                    .addAllPublicKey(allEphemeralPublicKeyList)
                    .build();

            return msg.toByteArray();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | InvalidKeySpecException | IllegalBlockSizeException e1) {
            e1.printStackTrace();
        }
        return new byte[0];
    }

    public void decAdd(ArrayList<byte[]> messages) {
        for (byte[] m : messages) {
            SignalProtos.RatchetedDynamicMulticastMessage msg = null;
            try {
                msg = SignalProtos.RatchetedDynamicMulticastMessage.parseFrom(m);
            } catch (InvalidProtocolBufferException e) {
                e.printStackTrace();
            }
            SignalProtocolAddress ad = new SignalProtocolAddress(msg.getName(), 1);
            if (msg.getAction() == SignalProtos.RatchetedDynamicMulticastMessage.Action.ADD) {
                try {
                    SessionRecord sessionRecord = loadSession(ad);
                    byte[] bytes = decrypt(msg, sessionRecord);
                    StorageProtos.RatchetDynamicMulticastAddStructure rdmm;
                    rdmm = StorageProtos.RatchetDynamicMulticastAddStructure.parseFrom(bytes);
                    //recupère le tag
                    byte[] tag = rdmm.getTag().toByteArray();
                    //get newMAcKey
                    ByteString new_mac_key = rdmm.getMacKey();
                    verifyMac(msg, sessionRecord, tag, new_mac_key);
                    storeSession(ad, sessionRecord);

                } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidKeySpecException | IOException | BadPaddingException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private byte[] decrypt(SignalProtos.RatchetedDynamicMulticastMessage msg, SessionRecord sessionRecord) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        ByteString ownEphemeralSecretKey = sessionRecord.getSessionState().getOwnEphemeralSecretKey();
        PKCS8EncodedKeySpec eSecKeySpec = new PKCS8EncodedKeySpec(ownEphemeralSecretKey.toByteArray());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey rsa_key = keyFactory.generatePrivate(eSecKeySpec);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, rsa_key);
        byte[] encodedKey = new byte[0];
        for (ByteString wrap : msg.getWrapList()) {
            try {
                encodedKey = cipher.doFinal(wrap.toByteArray());
            } catch (BadPaddingException e) {
//                            e.printStackTrace();
            }
        }
        SecretKey aes = new SecretKeySpec(encodedKey, "AES");
        cipher = Cipher.getInstance("AES"); //FIXME use AES/ECB/PKCS5Padding ?
        cipher.init(Cipher.DECRYPT_MODE, aes);
        return cipher.doFinal(msg.getCipher().toByteArray());
    }


    public byte[] dec(byte[] m) {
        SignalProtos.RatchetedDynamicMulticastMessage msg = null;
        try {
            msg = SignalProtos.RatchetedDynamicMulticastMessage.parseFrom(m);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
            return "".getBytes();
        }
        System.out.println(msg.getName());
        SignalProtocolAddress ad = new SignalProtocolAddress(msg.getName(), 1);
        if (msg.getAction() == SignalProtos.RatchetedDynamicMulticastMessage.Action.ENC) {
            try {
                //recupere les infos de session
                SessionRecord sessionRecord = loadSession(ad);
                byte[] bytes = decrypt(msg, sessionRecord);
                StorageProtos.RatchetDynamicMulticastEncStructure rdmm;
                rdmm = StorageProtos.RatchetDynamicMulticastEncStructure.parseFrom(bytes);
                //recupère le tag
                byte[] tag = rdmm.getTag().toByteArray();
                ByteString new_mac_key = rdmm.getMacKey();
                verifyMac(msg, sessionRecord, tag, new_mac_key);

                //recupère les ratchet key public et privées
                StorageProtos.RatchetDynamicMulticastMessageStructure message;
                message = rdmm.getMessage();

                ByteString secSigEphemeral = message.getSecretRatchetKey();
                ByteString pubSigEphemeral = message.getPublicRatchetKey();
                ECPrivateKey ourNewSigEphemeralPrivate = Curve.decodePrivatePoint(secSigEphemeral.toByteArray());
                ECPublicKey ourNewSigEphemeralPublic = Curve.decodePoint(pubSigEphemeral.toByteArray(), 0);

                //recompose une KeyPair
                ECKeyPair ourNewSigEphemeralKeyPair = new ECKeyPair(ourNewSigEphemeralPublic, ourNewSigEphemeralPrivate);

                if (ourNewSigEphemeralKeyPair.equals(sessionRecord.getSessionState().getSenderRatchetKeyPair())==false) {
                    RootKey rootKey = sessionRecord.getSessionState().getReceiverRootKey();//FIXME recuperer aussi cle publique
                    ECPublicKey theirSigEphemeral = sessionRecord.getSessionState().getLatestReceiverRatchetKey();
                    Pair<RootKey, ChainKey> chain = rootKey.createChain(theirSigEphemeral, ourNewSigEphemeralKeyPair);
                    SessionState currentState = sessionRecord.getSessionState();
                    sessionRecord.getSessionState().setRootKey(chain.first());
                    sessionRecord.getSessionState().setPreviousCounter(Math.max(currentState.getSenderChainKey().getIndex() - 1, 0));
                    sessionRecord.getSessionState().setSenderChain(ourNewSigEphemeralKeyPair, chain.second());

                }

                //ajout Celine
                //fait même maj des chain key/message key que celui qui fait le encrypt Signal
                ChainKey chainKey = sessionRecord.getSessionState().getSenderChainKey();
                sessionRecord.getSessionState().setSenderChainKey(chainKey.getNextChainKey());//FIXME c'est la le pb, n'enregistre pas l'avancée de l'index des chain key!
              //  System.out.println("fin dec2, chainkey index =" +  sessionRecord.getSessionState().getSenderChainKey().getIndex());
                //fin ajout Céline

                storeSession(ad, sessionRecord);

                return message.getText().toByteArray();

            } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidKeySpecException | IOException | BadPaddingException | org.whispersystems.libsignal.InvalidKeyException e) {
                e.printStackTrace();
            }
        }
        return new byte[0];
    }

    private void verifyMac(SignalProtos.RatchetedDynamicMulticastMessage msg, SessionRecord sessionRecord, byte[] tag, ByteString new_mac_key) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        SecretKeySpec new_mac_key_practical = new SecretKeySpec(new_mac_key.toByteArray(), "HmacSHA256");
        //recupère la liste de clés ephémères
        List<ByteString> allEphemeralPublicKey = msg.getPublicKeyList();
        //verifie le tag
        byte[] macKey = sessionRecord.getSessionState().getMacKey();
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec practicalMacKey = new SecretKeySpec(macKey, "HmacSHA256");
        sha256_HMAC.init(practicalMacKey);
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.write(new_mac_key.toByteArray());
        for (Iterator<ByteString> i = allEphemeralPublicKey.iterator(); i.hasNext(); ) {
            ByteString item = i.next();
            data.write(item.toByteArray());
        }
        byte[] verif_tag = sha256_HMAC.doFinal(data.toByteArray());
        assert Arrays.equals(verif_tag, tag) : "Mac verification failed";
        StorageProtos.SessionStructure.RatchetDynamicMulticastStructure rdms;
        rdms = sessionRecord.getSessionState().getRatchetDynamicMulticastStructure();
        StorageProtos.SessionStructure.RatchetDynamicMulticastStructure build = rdms.toBuilder()
                .setMacKey(new_mac_key)
                .clearAllEphemeralPublicKey()
                .addAllAllEphemeralPublicKey(allEphemeralPublicKey).build();
        sessionRecord.getSessionState().setRatchetDynamicMulticastStructure(build);
    }

    public ArrayList<byte[]> addjoin(PublicKey newDevicePublicKey) {

        ArrayList<byte[]> messages = new ArrayList<byte[]>();
        try {
            Map<SignalProtocolAddress, byte[]> allSessions = getAllSessions();
            for (SignalProtocolAddress ad : allSessions.keySet()) {
                byte[] bytes = allSessions.get(ad);
                SessionRecord sessionRecord = new SessionRecord(bytes);
                List<ByteString> allEphemeralPublicKey = sessionRecord.getSessionState().getAllEphemeralPublicKey();
                allEphemeralPublicKey.add(ByteString.copyFrom(newDevicePublicKey.getEncoded()));
                if (getDevicesPublicKeys().size() > 0) {//FIXME initialiser le DevicesPublicKeys avec la clé du device et passer le compteur à 1
                    byte[] msg = add(ad, allEphemeralPublicKey);
                    messages.add(msg);
                }


            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        updateAllEphemeralPubKey(newDevicePublicKey);
        addDeviceKey(newDevicePublicKey);
        byte[] joinmsg = join(newDevicePublicKey);
        messages.add(joinmsg);
        return messages;
    }

    private class EphemaralUpdater {
        private SignalProtocolAddress ad;
        private SessionRecord sessionRecord;
        private byte[] newMacKey;
        private List<ByteString> allEphemeralPublicKeyList;
        private byte[] tag;

        public EphemaralUpdater(SignalProtocolAddress ad, SessionRecord sessionRecord) {
            this.ad = ad;
            this.sessionRecord = sessionRecord;
        }

        public byte[] getNewMacKey() {
            return newMacKey;
        }

        public List<ByteString> getAllEphemeralPublicKeyList() {
            return allEphemeralPublicKeyList;
        }

        public byte[] getTag() {
            return tag;
        }

        public EphemaralUpdater invoke() throws NoSuchAlgorithmException, InvalidKeyException, IOException {
            StorageProtos.SessionStructure.RatchetDynamicMulticastStructure rdms;
            rdms = sessionRecord.getSessionState().getStructure().getRatchetDynamicMulticastStructure();
            // generate new MACKey
            ByteString preMacKey = rdms.getMacKey();
            newMacKey = KeyGenerator.getInstance("HmacSHA256").generateKey().getEncoded();
            // generate new ephemeral key
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(512);
            KeyPair ephemeralRDMKeyPair = keyGen.genKeyPair();
            ByteString pubk = ByteString.copyFrom(ephemeralRDMKeyPair.getPublic().getEncoded());
            ByteString prik = ByteString.copyFrom(ephemeralRDMKeyPair.getPrivate().getEncoded());
            // remove previous ephemeral public key from all devices public key list
            allEphemeralPublicKeyList = new ArrayList<>(rdms.getAllEphemeralPublicKeyList());
            allEphemeralPublicKeyList.remove(rdms.getOwnEphemeralPublicKey());
            // add new one in device public key
            allEphemeralPublicKeyList.add(pubk);
            // update RDM structure in session state
            StorageProtos.SessionStructure.RatchetDynamicMulticastStructure new_rmds;
            new_rmds = rdms.toBuilder().setMacKey(ByteString.copyFrom(newMacKey))
                    .clearAllEphemeralPublicKey()
                    .addAllAllEphemeralPublicKey(allEphemeralPublicKeyList)
                    .setOwnEphemeralPublicKey(pubk)
                    .setOwnEphemeralSecretKey(prik)
                    .build();
            sessionRecord.getSessionState().setRatchetDynamicMulticastStructure(new_rmds);
            storeSession(ad, sessionRecord);
            // build tag with all ephemeral pub keys + new mac key with pre mac key
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec practicalPreMacKey = new SecretKeySpec(preMacKey.toByteArray(), "HmacSHA256");
            sha256_HMAC.init(practicalPreMacKey);
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            data.write(newMacKey);
            for (Iterator<ByteString> i = allEphemeralPublicKeyList.iterator(); i.hasNext(); ) {
                ByteString item = i.next();
                data.write(item.toByteArray());
            }
            tag = sha256_HMAC.doFinal(data.toByteArray());
            return this;
        }
    }
}