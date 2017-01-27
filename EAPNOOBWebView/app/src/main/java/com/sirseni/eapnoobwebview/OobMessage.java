package com.sirseni.eapnoobwebview;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.util.Log;

/**
 * Created by root on 1/27/17.
 */
public class OobMessage {
    private static final String PREF_OOB_MESSAGE = "oob_message";
    private static final String DEFAULT_OOB_MESSAGE = null;
    private static final String TAG = "OobMessage";
    //private static String sOobMessage = null;
    private static final Object sOobLock = new Object();

    public static void SetOob(Context c, String s) {
        synchronized(sOobLock) {
            Log.i(TAG, "Setting Oob: " + s);
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(c);
            prefs.edit().putString(PREF_OOB_MESSAGE, s).commit();
        }
    }

    public static String GetAccount(Context c) {
        synchronized (sOobLock) {

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(c);
            String oob_message = prefs.getString(PREF_OOB_MESSAGE, DEFAULT_OOB_MESSAGE);
            return oob_message;
        }
    }
}
