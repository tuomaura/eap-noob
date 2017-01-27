package com.sirseni.eapnoobwebview;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

public class WebActivity extends Activity {

    static String TAG = "WEB VIEW";
    WebView myWebView;
    String web_url;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web);
        Intent intent = getIntent();
        web_url = intent.getStringExtra("URL");

        myWebView = (WebView) findViewById(R.id.myWebView);
        myWebView.loadUrl(web_url);
        myWebView.setWebViewClient(new MyWebViewClient());
        myWebView.addJavascriptInterface(new WebAppInterface(this), "Android");
        myWebView.setWebChromeClient(new WebChromeClient());
        WebSettings webSettings = myWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);

    }

    // Use When the user clicks a link from a web page in your WebView
    private class MyWebViewClient extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            if (url.equals(web_url)) {
                Log.i(TAG, "HERE 1");
                OobMessage.SetOob(getApplicationContext(),null);
                myWebView.clearCache(true);
                //myWebView.clearHistory();
                /*getApplicationContext().deleteDatabase("webview.db");
                getApplicationContext().deleteDatabase("webviewCache.db");*/
                //return false;
            }
            Log.i(TAG, "HERE 2");
            myWebView.loadUrl(url);
           /* Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);*/
            return true;
        }
    }

    public class WebAppInterface {
        Context mContext;

        /** Instantiate the interface and set the context */
        WebAppInterface(Context c) {
            mContext = c;
        }

        /** Show a toast from the web page */
        @JavascriptInterface
        public void sendOOB(String oob_meesage) {
            OobMessage.SetOob(getApplicationContext(),oob_meesage);
            Toast.makeText(mContext, oob_meesage, Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onBackPressed() {
        if (myWebView.canGoBack()) {
            myWebView.goBack();
        } else {
            super.onBackPressed();
        }
    }

}
