package com.example.myapplication;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.KeyGenerator;

@RequiresApi(api = Build.VERSION_CODES.M)
public class MainActivity extends AppCompatActivity {

    public static String hashKey;
    public SharedPreferences mSharedPreferences;
    MCrypt mCrypt = new MCrypt();

    public MainActivity() {
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        //this.getSharedPreferences("secrets", 0).edit().clear().commit();
            if (getSharedPreferences("secrets", 0).getString("PassHash", "").equals("")) {
                Intent setNewPassword = new Intent(getApplicationContext(), SetPassword.class);
                startActivity(setNewPassword);
            } else {
                if (hashKey == null) {
                    Intent logIn = new Intent(getApplicationContext(), LoginActivity.class);
                    startActivity(logIn);
                }
            }

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                        .setAction("Action", null).show();
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if(hashKey != null) {
            TextView notebook = (TextView) findViewById(R.id.notebook);
            String encryptedStr = getSharedPreferences("notebook", 0).getString("NotebookContent", "");
            try {
                String decryptedNote = mCrypt.HexToASCII(mCrypt.byteArrayToHexString(mCrypt.decrypt(encryptedStr)));
                notebook.setText(decryptedNote);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void onStop()
    {
        super.onStop();
        TextView notebook = (TextView)
                findViewById(R.id.notebook);
        String note = notebook.getText().toString();
        try {
            byte[] encryptedNote = MCrypt.encrypt(note);
            mSharedPreferences = getSharedPreferences("notebook", 0);
            SharedPreferences.Editor editor = mSharedPreferences.edit();
            String encryptedStr = MCrypt.byteArrayToHexString(encryptedNote);
            editor.putString("NotebookContent", encryptedStr);
            editor.apply();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);

    }

    public void go(View view) {
        Intent logIn = new Intent(getApplicationContext(), ChangePasswordActivity.class);
        startActivity(logIn);
    }
}

