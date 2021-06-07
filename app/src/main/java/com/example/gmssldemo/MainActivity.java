package com.example.gmssldemo;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
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

        checkPermission();

        TextView versionTv = findViewById(R.id.version_text);
        String[] version = GmSSL.getVersions();
        StringBuilder sb = new StringBuilder();
        for (String ver : version) {
            sb.append(ver).append(" ");
        }
        versionTv.setText(sb.toString());

        // sm2 加密验证
        genSM2KeyPairs("/sdcard/sm2");
        String source = "hello gmssl!!!  123456";
        byte[] sm2_encrypt = sm2Enc(source.getBytes(), source.getBytes().length);

        byte[] decrypt = sm2Dec(sm2_encrypt, sm2_encrypt.length);
        String decryptStr = new String(decrypt);
        Log.e(TAG, "decrypt str: " + decryptStr);

    }

    public boolean checkPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && checkSelfPermission(
                Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{
                    Manifest.permission.READ_EXTERNAL_STORAGE,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE
            }, 1);

        }
        return false;
    }

    public native byte[] aesEnc(byte[] in, int len, byte[] key);
    public native byte[] aesDec(byte[] in, int len, byte[] key);
    public native byte[] sha1(byte[] in, int len);

    public native int genSM2KeyPairs(String path);
    public native byte[] sm2Enc(byte[] in, int len);
    public native byte[] sm2Dec(byte[] in, int len);
    public native byte[] sm2Sign(byte[] in, int len);
    public native int sm2Verify(byte[] in, int len, byte[] sign, int signLen);

    public native byte[] sm3(byte[] in, int len);
    public native byte[] sm4Enc(byte[] in, int len, byte[] key);
    public native byte[] sm4Dec(byte[] in, int len, byte[] key);


    public native byte[] rsaEnc(byte[] key, byte[] src);
    public native byte[] rsaDes(byte[] key, byte[] src);
    public native byte[] rsaSign(byte[] key, byte[] src);
    public native int rsaVerify(byte[] key, byte[] src, byte[] sign);
}
