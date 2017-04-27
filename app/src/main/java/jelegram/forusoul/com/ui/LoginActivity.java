package jelegram.forusoul.com.ui;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import jelegram.forusoul.com.BuildConfig;
import jelegram.forusoul.com.R;
import jelegram.forusoul.com.connection.ConnectionManager;
import jelegram.forusoul.com.protocol.ReqAuthSendCode;

public class LoginActivity extends Activity {
    private static final String TAG = "LoginActivity";

    private EditText mPhoneNumberEditor = null;

    public static void invoke(Context context) {
        Intent intent = new Intent(context, LoginActivity.class);
        context.startActivity(intent);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        mPhoneNumberEditor = (EditText) findViewById(R.id.edit_phone_number);

        findViewById(R.id.btn_Start).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String inputPhoneNumber = mPhoneNumberEditor.toString();
                if (TextUtils.isEmpty(inputPhoneNumber)) {
                    if (BuildConfig.DEBUG) {
                        Log.e(TAG, "onCreate(), Input phone number is empty");
                    }
                    return;
                }
                requestSendCode(inputPhoneNumber);
            }
        });
    }

    private void requestSendCode(String phoneNumber) {
        ReqAuthSendCode sendCode = new ReqAuthSendCode(phoneNumber);
        try {
            ConnectionManager.getInstance().sendRequest(sendCode);
        } catch (Exception e) {
            if (BuildConfig.DEBUG) {
                Log.e(TAG, "requestSendCode(), Failed to request", e);
            }
        }
    }
}