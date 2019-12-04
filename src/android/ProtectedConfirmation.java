package com.davidebove.cordova.protectedconfirmation;

import android.app.Activity;
import android.security.ConfirmationAlreadyPresentingException;
import android.security.ConfirmationCallback;
import android.security.ConfirmationNotAvailableException;
import android.security.ConfirmationPrompt;
import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;

public class ProtectedConfirmation extends CordovaPlugin {

    private static final String ISSUPPORTED = "isSupported";
    private static final String INITKEY = "initKey";
    private static final String GETCERTIFICATECHAIN = "getCertificateChain";
    private static final String PRESENTPROMPT = "presentPrompt";
    private static final String PROTECTED_CONFIRMATION_KEYALIAS = ProtectedConfirmation.class.getCanonicalName();


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
                                callbackContext.success(isSupported());
                                break;
                            case INITKEY:
                                String challenge64 = args.getString(0);
                                callbackContext.success("");
                                break;
                            case GETCERTIFICATECHAIN: break;
                                Certificate[] chain = getCertificateChain();
                                callbackContext.success("CHAIN TODO");
                                break;
                            case PRESENTPROMPT:
                                String promptText = args.getString(0);
                                byte[] extraData = Base64.decode(args.getString(1), Base64.DEFAULT);
                                presentPrompt(promptText, extraData);
                                callbackContext.success("");
                                break;
                            default:
                                callbackContext.error("Invalid method call");
                                break;
                        }
                    } catch (Exception e) {
                        callbackContext.error("Error occurred while performing " + action);
                    }
                }
            });
        } catch (Exception e) {
            System.out.println("Error occurred while performing " + action + " : " + e.getMessage());
            callbackContext.error("Error occurred while performing " + action);
            return false;
        }
        return true;
    }

    private boolean isSupported() {
        return ConfirmationPrompt.isSupported(cordova.getActivity().getApplicationContext());
    }

    private Certificate[] getCertificateChain() throws KeyStoreException {
        KeyStore keyStore = null;
        keyStore = KeyStore.getInstance("AndroidKeyStore");
        if (keyStore != null) {
            keyStore.load(null);
            return keyStore.getCertificateChain(PROTECTED_CONFIRMATION_KEYALIAS);
        } else {
            return null;
        }
    }

    private void initKey(byte[] challenge) {
        // TODO
    }

    private void initKey_b64(String challenge64) {
        byte[] challenge = Base64.decode(challenge64, Base64.DEFAULT);
    }

    private void presentPrompt(String promptText, byte[] extraData) throws ConfirmationNotAvailableException, ConfirmationAlreadyPresentingException {
        Activity activity = cordova.getActivity();

        ConfirmationPrompt prompt = new ConfirmationPrompt.Builder(activity.getApplicationContext())
                .setExtraData(extraData)
                .setPromptText(promptText)
                .build();

        prompt.presentPrompt(activity.getMainExecutor(), createConfirmationCallback());
    }

    private ConfirmationCallback createConfirmationCallback() {
        return new ConfirmationCallback() {
            @Override
            public void onConfirmed(byte[] dataThatWasConfirmed) {
                super.onConfirmed(dataThatWasConfirmed);
            }

            @Override
            public void onDismissed() {
                super.onDismissed();
            }

            @Override
            public void onCanceled() {
                super.onCanceled();
            }

            @Override
            public void onError(Throwable e) {
                super.onError(e);
            }
        };
    }
}
