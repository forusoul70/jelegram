package jelegram.forusoul.com;

import android.app.Application;

import jelegram.forusoul.com.connection.ConnectionManager;

/**
 * Application
 */

public class ApplicationLoader extends Application {
    @Override
    public void onCreate() {
        super.onCreate();

        //
        ConnectionManager.getInstance();
    }
}
