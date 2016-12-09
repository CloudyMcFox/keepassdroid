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
package com.keepassdroid;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.AppOpsManager;
import android.app.KeyguardManager;
import android.content.ActivityNotFoundException;
import android.content.ClipData;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.text.InputType;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import com.android.keepass.KeePass;
import com.android.keepass.R;
import com.keepassdroid.FingerPrint.FingerPrintDialogFragment;
import com.keepassdroid.app.App;
import com.keepassdroid.compat.BackupManagerCompat;
import com.keepassdroid.compat.ClipDataCompat;
import com.keepassdroid.compat.EditorCompat;
import com.keepassdroid.compat.StorageAF;
import com.keepassdroid.database.edit.LoadDB;
import com.keepassdroid.database.edit.OnFinish;
import com.keepassdroid.dialog.PasswordEncodingDialogHelper;
import com.keepassdroid.fileselect.BrowserDialog;
import com.keepassdroid.intents.Intents;
import com.keepassdroid.settings.AppSettingsActivity;
import com.keepassdroid.utils.EmptyUtils;
import com.keepassdroid.utils.Interaction;
import com.keepassdroid.utils.UriUtil;
import com.keepassdroid.utils.Util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.security.cert.CertificateException;

public class PasswordActivity extends LockingActivity
{

    public static final String KEY_DEFAULT_FILENAME = "defaultFileName";
    private static final String KEY_FILENAME = "fileName";
    private static final String KEY_KEYFILE = "keyFile";
    private static final String KEY_PASSWORD = "password";
    private static final String KEY_LAUNCH_IMMEDIATELY = "launchImmediately";
    private static final String VIEW_INTENT = "android.intent.action.VIEW";

    private static final int FILE_BROWSE = 256;
    public static final int GET_CONTENT = 257;
    private static final int OPEN_DOC = 258;

    private Uri mDbUri = null;
    private Uri mKeyUri = null;
    private String mDbFileName = null; // used for a unique(ish) key for fingerprint (very bad solution to unique shared pref per db).
    private boolean mRememberKeyfile;
    private boolean m_fHasValidFingerPrintEnroll;
    SharedPreferences prefs;

    // fingerprint
    private FingerprintManager mFingerprintManager;
    private final String FINGERPRINT_KEY_NAME = "fingerprint_key";
    private Cipher mCipher;
    public static final String TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/"
            + KeyProperties.ENCRYPTION_PADDING_PKCS7;
    public static final String KEY_STORE = "AndroidKeyStore";
    public static final int AUTHENTICATION_DURATION_SECONDS = 30;
    private KeyguardManager mKeyguardManager;

    private FingerprintManager.CryptoObject mCryptoObject;


    public static void Launch(Activity act, String fileName) throws FileNotFoundException
    {
        Launch(act, fileName, "");
    }

    public static void Launch(Activity act, String fileName, String keyFile) throws FileNotFoundException
    {
        if (EmptyUtils.isNullOrEmpty(fileName)) {
            throw new FileNotFoundException();
        }

        Uri uri = UriUtil.parseDefaultFile(fileName);
        String scheme = uri.getScheme();

        if (!EmptyUtils.isNullOrEmpty(scheme) && scheme.equalsIgnoreCase("file")) {
            File dbFile = new File(uri.getPath());
            if (!dbFile.exists()) {
                throw new FileNotFoundException();
            }
        }

        Intent i = new Intent(act, PasswordActivity.class);
        i.putExtra(KEY_FILENAME, fileName);
        i.putExtra(KEY_KEYFILE, keyFile);

        act.startActivityForResult(i, 0);

    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data)
    {
        super.onActivityResult(requestCode, resultCode, data);

        switch (requestCode) {

            case KeePass.EXIT_NORMAL:
                setEditText(R.id.password, "");
                App.getDB().clear();
                break;

            case KeePass.EXIT_LOCK:
                setResult(KeePass.EXIT_LOCK);
                setEditText(R.id.password, "");
                finish();
                App.getDB().clear();
                break;
            case FILE_BROWSE:
                if (resultCode == RESULT_OK) {
                    String filename = data.getDataString();
                    if (filename != null) {
                        EditText fn = (EditText) findViewById(R.id.pass_keyfile);
                        fn.setText(filename);
                        mKeyUri = UriUtil.parseDefaultFile(filename);
                    }
                }
                break;
            case GET_CONTENT:
            case OPEN_DOC:
                if (resultCode == RESULT_OK) {
                    if (data != null) {
                        Uri uri = data.getData();
                        if (uri != null) {
                            if (requestCode == GET_CONTENT) {
                                uri = UriUtil.translate(this, uri);
                            }
                            String path = uri.toString();
                            if (path != null) {
                                EditText fn = (EditText) findViewById(R.id.pass_keyfile);
                                fn.setText(path);

                            }
                            mKeyUri = uri;
                        }
                    }
                }
                break;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        Intent i = getIntent();

        prefs = PreferenceManager.getDefaultSharedPreferences(this);
        mRememberKeyfile = prefs.getBoolean(getString(R.string.keyfile_key), getResources().getBoolean(R.bool.keyfile_default));

        setContentView(R.layout.password);
        mKeyguardManager = (KeyguardManager) getSystemService(this.KEYGUARD_SERVICE);
        new InitTask().execute(i);
    }

    @Override
    protected void onResume()
    {
        super.onResume();

        // If the application was shutdown make sure to clear the password field, if it
        // was saved in the instance state
        if (App.isShutdown()) {
            TextView password = (TextView) findViewById(R.id.password);
            password.setText("");
        }

        // Clear the shutdown flag
        App.clearShutdown();
    }

    private void retrieveSettings()
    {
        String defaultFilename = prefs.getString(KEY_DEFAULT_FILENAME, "");
        if (!EmptyUtils.isNullOrEmpty(mDbUri.getPath()) && UriUtil.equalsDefaultfile(mDbUri, defaultFilename)) {
            CheckBox checkbox = (CheckBox) findViewById(R.id.default_database);
            checkbox.setChecked(true);
        }
    }

    private Uri getKeyFile(Uri dbUri)
    {
        if (mRememberKeyfile) {

            return App.getFileHistory().getFileByName(dbUri);
        } else {
            return null;
        }
    }

    private void populateView()
    {
        ImageButton ibFingerPrint = (ImageButton) findViewById(R.id.fingerprint_button);
        ibFingerPrint.setEnabled(false);
        ibFingerPrint.setVisibility(View.INVISIBLE);

        ibFingerPrint.setOnClickListener(new View.OnClickListener()
        {
            public void onClick(View v)
            {
                FingerprintScan(false, false);
            }
        });

        String db = (mDbUri == null) ? "" : mDbUri.toString();
        setEditText(R.id.filename, db);

        String key = (mKeyUri == null) ? "" : mKeyUri.toString();
        setEditText(R.id.pass_keyfile, key);

        boolean fCanEnrollFingerPrint = true;
        if (this.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(this, "Fingerprint authentication permission not enabled", Toast.LENGTH_LONG).show();
            fCanEnrollFingerPrint = false;
            requestPermissions(new String[]{Manifest.permission.USE_FINGERPRINT}, 0); //Listen for result?
        }

        if (fCanEnrollFingerPrint) {
            mFingerprintManager =
                    (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
            // Has valid fingerprint to authenticate with:
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                //Fingerprint API only available on from Android 6.0 (M)
                if (!mFingerprintManager.isHardwareDetected()) {
                    // Device doesn't support fingerprint authentication
                    fCanEnrollFingerPrint = false;
                } else if (!mFingerprintManager.hasEnrolledFingerprints()) {
                    // User hasn't enrolled any fingerprints to authenticate with
                    fCanEnrollFingerPrint = false;
                }
            }
        }

        // if already has a valid fingerprint or doesn't have the ability to enroll fingerprint disable the option
        if (m_fHasValidFingerPrintEnroll) {
            ibFingerPrint.setEnabled(true);
            ibFingerPrint.setVisibility(View.VISIBLE);
        }
        if (!fCanEnrollFingerPrint) {
            // set fingerprint enrolled pref to false to reset if fingerprint in system is removed
            prefs.edit().putBoolean(mDbFileName + getString(R.string.fingerprint_enrolled_key), false).apply();
        }

        if (!fCanEnrollFingerPrint || m_fHasValidFingerPrintEnroll) {
            CheckBox cbFingerPrint = (CheckBox) findViewById(R.id.cbFingerPrintEnroll);
            cbFingerPrint.setEnabled(false);
            cbFingerPrint.setVisibility(View.INVISIBLE);
        }
        if (fCanEnrollFingerPrint && m_fHasValidFingerPrintEnroll){
            // fingerprint enrolled and ready
            FingerprintScan(false, false);
        }
    }

    private void FingerprintScan(boolean fInitCipherOnly, boolean fEnroll)
    {
        // try catch this
        try {

            if (initCipher(fEnroll)) {
                mCryptoObject = new FingerprintManager.CryptoObject(mCipher);

                if (!fInitCipherOnly) {
                    FingerPrintDialogFragment fragment
                            = new FingerPrintDialogFragment();
                    Bundle args = new Bundle();
                    args.putBoolean("enroll", fEnroll);
                    fragment.setArguments(args);

                    fragment.setCryptoObject(mCryptoObject);
                    fragment.show(getFragmentManager(), "DIALOG_FRAGMENT");
                }
            }
        } catch (Exception e) {
            // Log this123
        }
    }

    public void LoadDBFromFingerprintSuccess(boolean fEnrolling)
    {
        // get PW and load
        // If authenticated then get pw. (move this to post authentication)
        String encPass = prefs.getString(mDbFileName + getString(R.string.encrypted_pass), null);

        if (!fEnrolling) {
            loadDatabase(encPass, mKeyUri, false, true);
        } else {
            loadDatabase(getEditText(R.id.password), mKeyUri, true /*enroll*/, false);
        }
    }

    private void errorMessage(CharSequence text)
    {
        Toast.makeText(this, text, Toast.LENGTH_LONG).show();
    }


    private void errorMessage(int resId)
    {
        Toast.makeText(this, resId, Toast.LENGTH_LONG).show();
    }

    private class DefaultCheckChange implements CompoundButton.OnCheckedChangeListener
    {

        @Override
        public void onCheckedChanged(CompoundButton buttonView,
                                     boolean isChecked)
        {

            String newDefaultFileName;

            if (isChecked) {
                newDefaultFileName = mDbUri.toString();
            } else {
                newDefaultFileName = "";
            }

            SharedPreferences.Editor editor = prefs.edit();
            editor.putString(KEY_DEFAULT_FILENAME, newDefaultFileName);
            EditorCompat.apply(editor);

            BackupManagerCompat backupManager = new BackupManagerCompat(PasswordActivity.this);
            backupManager.dataChanged();

        }

    }

    private class OkClickHandler implements View.OnClickListener
    {
        public void onClick(View view)
        {
            // Handle Enroll fingerprint (need to move to after PW?)
            boolean fEnrollFingerprint = false;
            CheckBox cbFingerPrint = (CheckBox) findViewById(R.id.cbFingerPrintEnroll);
            if (cbFingerPrint.isEnabled() && View.VISIBLE == cbFingerPrint.getVisibility() && cbFingerPrint.isChecked()) {
                fEnrollFingerprint = true;
            }

            String pass = getEditText(R.id.password);
            String key = getEditText(R.id.pass_keyfile);

            if (fEnrollFingerprint) {
                FingerprintScan(false, true /*enrolling*/);
                // load db will be called on auth success
            } else {
                loadDatabase(pass, key, false, false);
            }
        }
    }

    private void loadDatabase(String pass, String keyfile, boolean fEnrollFingerprint, boolean fFingerprintLogInSuccess)
    {
        loadDatabase(pass, UriUtil.parseDefaultFile(keyfile), fEnrollFingerprint, fFingerprintLogInSuccess);
    }

    private void loadDatabase(String pass, Uri keyfile, boolean fEnrollFingerprint, boolean fFingerprintLogInSuccess)
    {
        if (pass.length() == 0 && (keyfile == null || keyfile.toString().length() == 0)) {
            errorMessage(R.string.error_nopass);
            return;
        }

        // Clear before we load
        Database db = App.getDB();
        db.clear();

        // Clear the shutdown flag
        App.clearShutdown();

        Handler handler = new Handler();
        LoadDB task = new LoadDB(db, PasswordActivity.this, mDbUri, pass, keyfile, new AfterLoad(handler, db), fEnrollFingerprint, fFingerprintLogInSuccess);
        ProgressTask pt = new ProgressTask(PasswordActivity.this, task, R.string.loading_database);
        pt.run();
    }

    private String getEditText(int resId)
    {
        return Util.getEditText(this, resId);
    }

    private void setEditText(int resId, String str)
    {
        TextView te = (TextView) findViewById(resId);
        assert (te == null);

        if (te != null) {
            te.setText(str);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu)
    {
        super.onCreateOptionsMenu(menu);

        MenuInflater inflate = getMenuInflater();
        inflate.inflate(R.menu.password, menu);

        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item)
    {
        switch (item.getItemId()) {
            case R.id.menu_about:
                AboutDialog dialog = new AboutDialog(this);
                dialog.show();
                return true;

            case R.id.menu_app_settings:
                AppSettingsActivity.Launch(this);
                return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private final class AfterLoad extends OnFinish
    {
        private Database db;

        public AfterLoad(Handler handler, Database db)
        {
            super(handler);

            this.db = db;
        }

        @Override
        public void run()
        {
            if (db.passwordEncodingError) {
                PasswordEncodingDialogHelper dialog = new PasswordEncodingDialogHelper();
                dialog.show(PasswordActivity.this, new OnClickListener()
                {

                    @Override
                    public void onClick(DialogInterface dialog, int which)
                    {
                        GroupActivity.Launch(PasswordActivity.this);
                    }

                });
            } else if (mSuccess) {
                GroupActivity.Launch(PasswordActivity.this);
            } else {
                displayMessage(PasswordActivity.this);
            }
        }
    }

    private class InitTask extends AsyncTask<Intent, Void, Integer>
    {
        String password = "";
        boolean launch_immediately = false;

        @Override
        protected Integer doInBackground(Intent... args)
        {
            Intent i = args[0];
            String action = i.getAction();
            ;
            if (action != null && action.equals(VIEW_INTENT)) {
                Uri incoming = i.getData();
                mDbUri = incoming;

                mKeyUri = ClipDataCompat.getUriFromIntent(i, KEY_KEYFILE);

                if (incoming == null) {
                    return R.string.error_can_not_handle_uri;
                } else if (incoming.getScheme().equals("file")) {
                    String fileName = incoming.getPath();

                    if (fileName.length() == 0) {
                        // No file name
                        return R.string.FileNotFound;
                    }

                    File dbFile = new File(fileName);
                    if (!dbFile.exists()) {
                        // File does not exist
                        return R.string.FileNotFound;
                    }

                    if (mKeyUri == null)
                        mKeyUri = getKeyFile(mDbUri);
                } else if (incoming.getScheme().equals("content")) {
                    if (mKeyUri == null)
                        mKeyUri = getKeyFile(mDbUri);
                } else {
                    return R.string.error_can_not_handle_uri;
                }
                password = i.getStringExtra(KEY_PASSWORD);
                launch_immediately = i.getBooleanExtra(KEY_LAUNCH_IMMEDIATELY, false);

            } else {
                mDbUri = UriUtil.parseDefaultFile(i.getStringExtra(KEY_FILENAME));
                mKeyUri = UriUtil.parseDefaultFile(i.getStringExtra(KEY_KEYFILE));
                password = i.getStringExtra(KEY_PASSWORD);
                launch_immediately = i.getBooleanExtra(KEY_LAUNCH_IMMEDIATELY, false);

                if (mKeyUri == null || mKeyUri.toString().length() == 0) {
                    mKeyUri = getKeyFile(mDbUri);
                }
            }

            // Get fingerprint settings
            mDbFileName = mDbUri.toString().substring(mDbUri.toString().lastIndexOf('/') + 1, mDbUri.toString().length());
            m_fHasValidFingerPrintEnroll = prefs.getBoolean(mDbFileName + getString(R.string.fingerprint_enrolled_key), getResources().getBoolean(R.bool.valid_fingerprint_enrolled_default));
            return null;
        }

        public void onPostExecute(Integer result)
        {
            if (result != null) {
                Toast.makeText(PasswordActivity.this, result, Toast.LENGTH_LONG).show();
                finish();
                return;
            }

            populateView();

            Button confirmButton = (Button) findViewById(R.id.pass_ok);
            confirmButton.setOnClickListener(new OkClickHandler());

            CheckBox checkBox = (CheckBox) findViewById(R.id.show_password);
            // Show or hide password
            checkBox.setOnCheckedChangeListener(new OnCheckedChangeListener()
            {

                public void onCheckedChanged(CompoundButton buttonView,
                                             boolean isChecked)
                {
                    TextView password = (TextView) findViewById(R.id.password);

                    if (isChecked) {
                        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
                    } else {
                        password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
                    }
                }

            });

            if (password != null) {
                TextView tv_password = (TextView) findViewById(R.id.password);
                tv_password.setText(password);
            }

            CheckBox defaultCheck = (CheckBox) findViewById(R.id.default_database);
            defaultCheck.setOnCheckedChangeListener(new DefaultCheckChange());

            ImageButton browse = (ImageButton) findViewById(R.id.browse_button);
            browse.setOnClickListener(new View.OnClickListener()
            {
                public void onClick(View v)
                {
                    if (StorageAF.useStorageFramework(PasswordActivity.this)) {
                        Intent i = new Intent(StorageAF.ACTION_OPEN_DOCUMENT);
                        i.addCategory(Intent.CATEGORY_OPENABLE);
                        i.setType("*/*");
                        startActivityForResult(i, OPEN_DOC);
                    } else {
                        Intent i = new Intent(Intent.ACTION_GET_CONTENT);
                        i.addCategory(Intent.CATEGORY_OPENABLE);
                        i.setType("*/*");

                        try {
                            startActivityForResult(i, GET_CONTENT);
                        } catch (ActivityNotFoundException e) {
                            lookForOpenIntentsFilePicker();
                        }
                    }
                }

                private void lookForOpenIntentsFilePicker()
                {
                    if (Interaction.isIntentAvailable(PasswordActivity.this, Intents.OPEN_INTENTS_FILE_BROWSE)) {
                        Intent i = new Intent(Intents.OPEN_INTENTS_FILE_BROWSE);

                        // Get file path parent if possible
                        try {
                            if (mDbUri != null && mDbUri.toString().length() > 0) {
                                if (mDbUri.getScheme().equals("file")) {
                                    File keyfile = new File(mDbUri.getPath());
                                    File parent = keyfile.getParentFile();
                                    if (parent != null) {
                                        i.setData(Uri.parse("file://" + parent.getAbsolutePath()));
                                    }
                                }
                            }
                        } catch (Exception e) {
                            // Ignore
                        }

                        try {
                            startActivityForResult(i, FILE_BROWSE);
                        } catch (ActivityNotFoundException e) {
                            showBrowserDialog();
                        }
                    } else {
                        showBrowserDialog();
                    }
                }

                private void showBrowserDialog()
                {
                    BrowserDialog diag = new BrowserDialog(PasswordActivity.this);
                    diag.show();
                }
            });

            retrieveSettings();

            if (launch_immediately) {
                loadDatabase(password, mKeyUri, false, false);
            }
        }
    }

    private boolean initCipher(boolean fEnroll)
    {
        try {
            if (fEnroll) {
                SecretKey key = createKey();
                mCipher = Cipher.getInstance(TRANSFORMATION);
                mCipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] encryptionIv = mCipher.getIV();
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString("encryptionIv", Base64.encodeToString(encryptionIv, Base64.DEFAULT));
                editor.apply();
                // store IV
            } else {
                KeyStore keyStore = KeyStore.getInstance(KEY_STORE);
                keyStore.load(null);
                SecretKey key = (SecretKey) keyStore.getKey(FINGERPRINT_KEY_NAME, null);
                mCipher = Cipher.getInstance(TRANSFORMATION);
                String base64EncryptionIv = prefs.getString("encryptionIv", null);
                byte[] encryptionIv = Base64.decode(base64EncryptionIv, Base64.DEFAULT);
                mCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(encryptionIv));
            }

            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | UserNotAuthenticatedException e) {
            Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
            if (intent != null) {
                startActivityForResult(intent, KeePass.REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
            }
            return false;
        } catch (CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            errorMessage("Failed to enroll fingerprint. Make sure a valid fingerprint is enrolled!\n" + e.getMessage());
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    private SecretKey createKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEY_STORE);
            keyGenerator.init(new KeyGenParameterSpec.Builder(FINGERPRINT_KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_DURATION_SECONDS)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to create a symmetric key", e);
        }
    }

    public Cipher getCipher() {
        return mCipher;
    }
}
