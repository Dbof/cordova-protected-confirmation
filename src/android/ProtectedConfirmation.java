package com.davidebove.cordova.protectedconfirmation;

import android.app.Activity;
import android.security.ConfirmationAlreadyPresentingException;
import android.security.ConfirmationCallback;
import android.security.ConfirmationNotAvailableException;
import android.security.ConfirmationPrompt;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class ProtectedConfirmation extends CordovaPlugin {

    private static final String ISSUPPORTED = "isSupported";
    private static final String INITKEY = "initKey";
    private static final String GETCERTIFICATECHAIN = "getCertificateChain";
    private static final String PRESENTPROMPT = "presentPrompt";
    private static final String PROTECTED_CONFIRMATION_KEYALIAS = ProtectedConfirmation.class.getCanonicalName();

    final String BEGIN = "-----BEGIN CERTIFICATE-----\n";
    final String END = "\n-----END CERTIFICATE-----|";


    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext)
            throws JSONException {
        try {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        switch(action) {
                            case ISSUPPORTED:
                                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, isSupported()));
                                break;
                            case INITKEY:
                                String challenge64 = args.getString(0);
                                initKey(challenge64);
                                callbackContext.success();
                                break;
                            case GETCERTIFICATECHAIN:
                                byte[] chain = getCertificateChain();
                                if (chain == null)
                                    callbackContext.error("Could not retrieve chain. Did you call " + INITKEY + " first?");
                                else
                                    callbackContext.success(chain);
                                break;
                            case PRESENTPROMPT:
                                // first check if signing key exists
                                if (!keyExists()) {
                                    callbackContext.error("Protected confirmation not yet available. Did you call " + INITKEY + " first?");
                                } else {
                                    String promptText = args.getString(0);
                                    byte[] extraData = Base64.decode(args.getString(1), Base64.DEFAULT);
                                    presentPrompt(promptText, extraData, callbackContext);
                                }
                                break;
                            default:
                                callbackContext.error("Invalid method call");
                        }
                    } catch (Exception e) {
                        System.err.println("Error while performing " + action);
                        callbackContext.error("Error occurred while performing " + action + ": " + e.getMessage());
                    }
                }
            });
        } catch (Exception e) {
            System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
            callbackContext.error("Error occurred while performing " + action);
        }
        return true;
    }

    private boolean isSupported() {
        return ConfirmationPrompt.isSupported(cordova.getActivity().getApplicationContext());
    }

    private byte[] getCertificateChain() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

        Certificate[] chain;
        if (keyStore != null) {
            keyStore.load(null);
            chain = keyStore.getCertificateChain(PROTECTED_CONFIRMATION_KEYALIAS);
        } else {
            return null;
        }

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for (Certificate c : chain) {
            byte[] cert64 = Base64.encode(c.getEncoded(), Base64.NO_WRAP);
            os.write(BEGIN.getBytes());
            os.write(cert64);
            os.write(END.getBytes());
        }
        return os.toByteArray();
    }

    private void initKey(String challenge64) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        byte[] challenge = Base64.decode(challenge64, Base64.DEFAULT);
        initKey(challenge);
    }

    private void initKey(byte[] challenge) throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(PROTECTED_CONFIRMATION_KEYALIAS, KeyProperties.PURPOSE_SIGN)
                .setUserConfirmationRequired(true)
                .setIsStrongBoxBacked(true)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setAttestationChallenge(challenge);
        kpg.initialize(builder.build());
        kpg.generateKeyPair();
    }

    private boolean keyExists() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        if (keyStore != null) {
            keyStore.load(null);
            return keyStore.containsAlias(PROTECTED_CONFIRMATION_KEYALIAS);
        }
        return false;
    }

    private void presentPrompt(String promptText, byte[] extraData, final CallbackContext callbackContext) throws ConfirmationNotAvailableException, ConfirmationAlreadyPresentingException {
        Activity activity = cordova.getActivity();

        ConfirmationPrompt prompt = new ConfirmationPrompt.Builder(activity.getApplicationContext())
                .setExtraData(extraData)
                .setPromptText(promptText)
                .build();

        prompt.presentPrompt(activity.getMainExecutor(), createConfirmationCallback(callbackContext));
    }

    private ConfirmationCallback createConfirmationCallback(final CallbackContext callbackContext) {
        return new ConfirmationCallback() {
            @Override
            public void onConfirmed(byte[] dataThatWasConfirmed) {
                super.onConfirmed(dataThatWasConfirmed);
                callbackContext.success(dataThatWasConfirmed);
            }

            @Override
            public void onDismissed() {
                super.onDismissed();
                callbackContext.error("Confirmation Prompt was dismissed!");
            }

            @Override
            public void onCanceled() {
                super.onCanceled();
                callbackContext.error("Confirmation Prompt was cancelled by the application!");
            }

            @Override
            public void onError(Throwable e) {
                super.onError(e);
                callbackContext.error("Error while showing Confirmation Prompt: " + e.getMessage());
            }
        };
    }
}
