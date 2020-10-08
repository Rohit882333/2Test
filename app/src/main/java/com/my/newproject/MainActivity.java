package com.my.newproject;

import android.app.Activity;
import android.os.Bundle;
import android.Manifest;
import android.content.pm.PackageManager;
import android.widget.Button;
import android.view.View;
import android.app.AlertDialog;
import android.support.v4.content.ContextCompat;
import android.support.v4.app.ActivityCompat;
import com.android.apksig.ApkSigner;
import java.io.File;
import java.security.KeyStore;
import java.util.Enumeration;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.LinkedList;
import java.security.cert.X509Certificate;
import java.util.List;

public class MainActivity extends Activity {
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_DENIED
            || ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_DENIED) {
            ActivityCompat.requestPermissions(this, new String[] {Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE}, 1000);
        }
        
        Button btn = findViewById(R.id.mainButton1);
        btn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View p1)
                {
                    String input_apk = "/storage/emulated/0/iBuilder/Ps Builder/app/src/bin/app.apk";
                    String output_apk = "/storage/emulated/0/signer_app.apk";
                    String keystore = "/storage/emulated/0/keystore.jks";
                    
                    String err = "";
                    try {
                        KeyStore instance = KeyStore.getInstance(KeyStore.getDefaultType());
                        char[] password = "88233386".toCharArray();
                        instance.load(null, password);
                        PrivateKey privateKey = (PrivateKey)instance.getKey(KeyStore.getDefaultType(), password);
                        Certificate[] certificateChain = instance.getCertificateChain(KeyStore.getDefaultType());
                        if (certificateChain == null || certificateChain.length == 0) {
                            throw new IllegalArgumentException("Unable to load certificates!");
                        }
                        List<X509Certificate> list = new LinkedList<X509Certificate>();
                        for (int i = 0; i < certificateChain.length; ++i) {
                            list.add((X509Certificate)certificateChain[i]);
                        }
                         new ApkSigner.Builder(new ApkSigner.SignerConfig.Builder("", "", "", ""))
                        .setCreatedBy("Ps Builder")
                        .setV1SigningEnabled(true)
                        .setV2SigningEnabled(true)
                        .setInputApk(new File(input_apk))
                        .setOutputApk(new File(output_apk))
                        .setOtherSignersSignaturesPreserved(false)
                        .build()
                        .sign();
                    } catch (Exception e) {
                        err = e.toString();
                    }
                    if (!err.equals("")) {
                        AlertDialog.Builder a = new AlertDialog.Builder(MainActivity.this);
                        a.setTitle("Error logs");
                        a.setMessage(err);
                        a.setPositiveButton("OK", null);
                        a.create().show();
                    }
                }
            });
    }
}
