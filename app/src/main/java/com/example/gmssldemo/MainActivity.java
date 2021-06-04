package com.example.gmssldemo;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";

    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView versionTv = findViewById(R.id.version_text);
        String[] version = GmSSL.getVersions();
        StringBuilder sb = new StringBuilder();
        for (String ver : version) {
            sb.append(ver).append(" ");
        }
        versionTv.setText(sb.toString());
    }


    public native byte[] aesEnc(byte[] in, int len, byte[] key);
    public native byte[] aesDec(byte[] in, int len, byte[] key);
    public native byte[] sha1(byte[] in, int len);

    public native int genSM2KeyPairs(String path);
    public native byte[] sm3(byte[] in, int len);
    public native byte[] sm4Enc(byte[] in, int len, byte[] key);
    public native byte[] sm4Dec(byte[] in, int len, byte[] key);
    public native byte[] sm2Enc(byte[] in, int len);
    public native byte[] sm2Dec(byte[] in, int len);
    public native byte[] sm2Sign(byte[] in, int len);
    public native int sm2Verify(byte[] in, int len, byte[] sign, int signLen);


    public native byte[] rsaEnc(byte[] key, byte[] src);
    public native byte[] rsaDes(byte[] key, byte[] src);
    public native byte[] rsaSign(byte[] key, byte[] src);
    public native int rsaVerify(byte[] key, byte[] src, byte[] sign);
}
