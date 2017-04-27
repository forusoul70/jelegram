package jelegram.forusoul.com.ui;

import android.app.Activity;
import android.os.Bundle;

public class LauncherActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LoginActivity.invoke(this);
        finish();
    }
}
