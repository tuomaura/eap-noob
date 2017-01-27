package com.sirseni.eapnoobwebview;

import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        final Button button = (Button) findViewById(R.id.button);
        button.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                EditText editText = (EditText) findViewById(R.id.url);
                String message = editText.getText().toString();

                if (message != null) {
                    Intent intent = new Intent(getApplicationContext(), WebActivity.class);
                    intent.putExtra("URL", message);
                    startActivity(intent);
                }
            }
        });
    }
}
