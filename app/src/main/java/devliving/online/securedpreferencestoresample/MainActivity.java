package devliving.online.securedpreferencestoresample;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.security.KeyStore;
import java.util.List;

import devliving.online.securedpreferencestore.DefaultRecoveryHandler;
import devliving.online.securedpreferencestore.SecuredPreferenceStore;

public class MainActivity extends AppCompatActivity {

    EditText text1;

    Button reloadButton, saveButton, imageDemoBtn;

    String TEXT_1 = "text_short";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        text1 =  findViewById(R.id.text_value_1);


        reloadButton =  findViewById(R.id.reload);
        saveButton = findViewById(R.id.save);
        imageDemoBtn = findViewById(R.id.tryFile);

        try {
            //not mandatory, can be null too
            String storeFileName = "secured preferences";
            //not mandatory, can be null too
            String keyPrefix = null;
            //it's better to provide one, and you need to provide the same key each time after the first time
            byte[] seedKey = "seedKey".getBytes();
            SecuredPreferenceStore.init(getApplicationContext(), storeFileName, keyPrefix, seedKey, new DefaultRecoveryHandler());

            //SecuredPreferenceStore.init(getApplicationContext(), null);
            setupStore();
        } catch (Exception e) {
            // Handle error.
            e.printStackTrace();
        }

        reloadButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    reloadData();
                } catch (Exception e) {
                    Log.e("SECURED-PREFERENCE", "", e);
                    Toast.makeText(MainActivity.this, "An exception occurred, see log for details", Toast.LENGTH_SHORT).show();
                }
            }
        });

        saveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    saveData();
                } catch (Exception e) {
                    Log.e("SECURED-PREFERENCE", "", e);
                    Toast.makeText(MainActivity.this, "An exception occurred, see log for details", Toast.LENGTH_SHORT).show();
                }
            }
        });

        imageDemoBtn.setOnClickListener(v -> {
            Intent intent = new Intent(this, FileDemoActivity.class);
            startActivity(intent);
        });
    }

    private void setupStore() {
        SecuredPreferenceStore.setRecoveryHandler(new DefaultRecoveryHandler(){
            @Override
            protected boolean recover(Exception e, KeyStore keyStore, List<String> keyAliases, SharedPreferences preferences) {
                Toast.makeText(MainActivity.this, "Encryption key got invalidated, will try to start over.", Toast.LENGTH_SHORT).show();
                return super.recover(e, keyStore, keyAliases, preferences);
            }
        });

        try {
            reloadData();
        } catch (Exception e) {
            Log.e("SECURED-PREFERENCE", "", e);
            Toast.makeText(this, "An exception occurred, see log for details", Toast.LENGTH_SHORT).show();
        }
    }

    void reloadData()  {
        SecuredPreferenceStore prefStore = SecuredPreferenceStore.getSharedInstance();

        String textShort = prefStore.getString(TEXT_1, null);


        text1.setText(textShort);
    }

    void saveData() {
        SecuredPreferenceStore prefStore = SecuredPreferenceStore.getSharedInstance();

        prefStore.edit().putString(TEXT_1, text1.length() > 0 ? text1.getText().toString() : null).apply();
    }
}
