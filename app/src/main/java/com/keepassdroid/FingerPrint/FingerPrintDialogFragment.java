package com.keepassdroid.FingerPrint;

import android.app.Activity;
import android.app.DialogFragment;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import com.android.keepass.R;
import com.keepassdroid.PasswordActivity;

public class FingerPrintDialogFragment extends DialogFragment
        implements TextView.OnEditorActionListener, FingerprintHandler.Callback {

    private Button mCancelButton;
    private View mFingerprintContent;

    private FingerprintManager.CryptoObject mCryptoObject;
    private FingerprintHandler mFingerprintUiHelper;
    private PasswordActivity mActivity;


    private boolean m_fEnroll = false;

    public FingerPrintDialogFragment()
    {
    }
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog);
        m_fEnroll = getArguments().getBoolean("enroll");
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        getDialog().setTitle("Sign in");
        View v = inflater.inflate(R.layout.fingerprint_dialog_container, container, false);
        mCancelButton = (Button) v.findViewById(R.id.cancel_button);
        if (!m_fEnroll) {
            mCancelButton.setOnClickListener(new View.OnClickListener()
            {
                @Override
                public void onClick(View view)
                {
                    dismiss();
                }
            });
        } else {
            mCancelButton.setEnabled(false);
            mCancelButton.setVisibility(View.INVISIBLE);
        }

        mFingerprintContent = v.findViewById(R.id.fingerprint_container);
        mFingerprintUiHelper = new FingerprintHandler(
                mActivity.getSystemService(FingerprintManager.class),
                (ImageView) v.findViewById(R.id.fingerprint_icon),
                (TextView) v.findViewById(R.id.fingerprint_status), this);
        mCancelButton.setText(R.string.cancel);
        mFingerprintContent.setVisibility(View.VISIBLE);

        if (!mFingerprintUiHelper.isFingerprintAuthAvailable()) {
            dismiss();
        }
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        mFingerprintUiHelper.startListening(mCryptoObject);
    }

    @Override
    public void onPause() {
        super.onPause();
        mFingerprintUiHelper.stopListening();
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        mActivity = (PasswordActivity) activity;
    }

    /**
     * Sets the crypto object to be passed in when authenticating with fingerprint.
     */
    public void setCryptoObject(FingerprintManager.CryptoObject cryptoObject) {
        mCryptoObject = cryptoObject;
    }

    @Override
    public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
        if (actionId == EditorInfo.IME_ACTION_GO) {
            return true;
        }
        return false;
    }

    @Override
    public void onAuthenticated() {
        // if enrolling all we need is authentication
        mActivity.LoadDBFromFingerprintSuccess(m_fEnroll);
        dismiss();
    }

    @Override
    public void onError() {
        dismiss();
    }
}