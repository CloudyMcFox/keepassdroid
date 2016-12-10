/*
 * Copyright 2009-2016 Brian Pellin.
 *     
 * This file is part of KeePassDroid.
 *
 *  KeePassDroid is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  KeePassDroid is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with KeePassDroid.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package com.keepassdroid.database.edit;

import java.io.FileNotFoundException;
import java.io.IOException;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.preference.PreferenceManager;
import android.util.Base64;

import com.android.keepass.R;
import com.keepassdroid.Database;
import com.keepassdroid.PasswordActivity;
import com.keepassdroid.app.App;
import com.keepassdroid.database.exception.ArcFourException;
import com.keepassdroid.database.exception.ContentFileNotFoundException;
import com.keepassdroid.database.exception.InvalidAlgorithmException;
import com.keepassdroid.database.exception.InvalidDBException;
import com.keepassdroid.database.exception.InvalidDBSignatureException;
import com.keepassdroid.database.exception.InvalidDBVersionException;
import com.keepassdroid.database.exception.InvalidKeyFileException;
import com.keepassdroid.database.exception.InvalidPasswordException;
import com.keepassdroid.database.exception.KeyFileEmptyException;

public class LoadDB extends RunnableOnFinish
{
    private Uri mUri;
    private String mFileName;
    private String mPass;
    private Uri mKey;
    private Database mDb;
    private Context mCtx;
    private boolean mRememberKeyfile;
    private boolean mEnrollFingerPrint;
    private SharedPreferences mPrefs;

    public static final String CHARSET_NAME = "UTF-8";


    public LoadDB(Database db, Context ctx, Uri uri, String pass, Uri key, OnFinish finish, boolean fEnrollFingerprint, boolean fFingerprintLogInSuccess)
    {
        super(finish);
        assert(!fEnrollFingerprint || !fFingerprintLogInSuccess);
        mDb = db;
        mCtx = ctx;
        mUri = uri;
        mFileName = uri.toString().substring( uri.toString().lastIndexOf('/')+1, uri.toString().length() );
        mPrefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        if (fFingerprintLogInSuccess) {
            // decrypt pass
            try {
                String base64EncryptedPassword = pass;
                byte[] encryptedPassword = Base64.decode(base64EncryptedPassword, Base64.DEFAULT);
                PasswordActivity passwordActCtx = (PasswordActivity) mCtx;
                byte[] passwordBytes = passwordActCtx.getCipher().doFinal(encryptedPassword);
                String password = new String(passwordBytes, CHARSET_NAME);
                mPass = password;
            } catch (Exception e) {
                // log here
                mPass = pass;
            }
        } else {
            mPass = pass;
        }
        mKey = key;
        mEnrollFingerPrint = fEnrollFingerprint;
        mRememberKeyfile = mPrefs.getBoolean(ctx.getString(R.string.keyfile_key), ctx.getResources().getBoolean(R.bool.keyfile_default));
    }

    @Override
    public void run()
    {
        try {
            mDb.LoadData(mCtx, mUri, mPass, mKey, mStatus);

            saveFileData(mUri, mKey);

        } catch (ArcFourException e) {
            finish(false, mCtx.getString(R.string.error_arc4));
            return;
        } catch (InvalidPasswordException e) {
            finish(false, mCtx.getString(R.string.InvalidPassword));
            return;
        } catch (ContentFileNotFoundException e) {
            finish(false, mCtx.getString(R.string.file_not_found_content));
            return;
        } catch (FileNotFoundException e) {
            finish(false, mCtx.getString(R.string.FileNotFound));
            return;
        } catch (IOException e) {
            finish(false, e.getMessage());
            return;
        } catch (KeyFileEmptyException e) {
            finish(false, mCtx.getString(R.string.keyfile_is_empty));
            return;
        } catch (InvalidAlgorithmException e) {
            finish(false, mCtx.getString(R.string.invalid_algorithm));
            return;
        } catch (InvalidKeyFileException e) {
            finish(false, mCtx.getString(R.string.keyfile_does_not_exist));
            return;
        } catch (InvalidDBSignatureException e) {
            finish(false, mCtx.getString(R.string.invalid_db_sig));
            return;
        } catch (InvalidDBVersionException e) {
            finish(false, mCtx.getString(R.string.unsupported_db_version));
            return;
        } catch (InvalidDBException e) {
            finish(false, mCtx.getString(R.string.error_invalid_db));
            return;
        } catch (OutOfMemoryError e) {
            finish(false, mCtx.getString(R.string.error_out_of_memory));
            return;
        }

        // succeeded, so store PW if we wanted to enroll FP
        if (mEnrollFingerPrint) {
           try {
               // Encrypt Pass
               PasswordActivity passCtx = (PasswordActivity) mCtx;
               byte[] passwordBytes = mPass.getBytes(CHARSET_NAME);
               byte[] encryptedPasswordBytes =  passCtx.getCipher().doFinal(passwordBytes);
               String encryptedPassword = Base64.encodeToString(encryptedPasswordBytes, Base64.DEFAULT);

               SharedPreferences.Editor editor = mPrefs.edit();
               editor.putString(mFileName + mCtx.getString(R.string.encrypted_pass), encryptedPassword);
               editor.putBoolean(mFileName + mCtx.getString(R.string.fingerprint_enrolled_key), true);
               editor.apply();
           } catch (Exception e) {
               // best effort
               // log here
               mPrefs.edit().putBoolean(mFileName + mCtx.getString(R.string.fingerprint_enrolled_key), false).apply();
           }
        }
        finish(true);
    }

    private void saveFileData(Uri uri, Uri key)
    {
        if (!mRememberKeyfile) {
            key = null;
        }

        App.getFileHistory().createFile(uri, key);
    }


}
