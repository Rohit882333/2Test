package com.my.newproject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyStoreM {
    
	private String certificateAlias;
	private String certificatePassword;
	private String keystorePassword;
	private String keystoreOutputPath;
	private String keystoreType;
	private java.security.KeyStore keystore;
	private StringBuilder logCat;
	private PrivateKey key;
	private X509Certificate certificate;

	private KeyStoreM(Builder builder){
		this.certificateAlias = builder.certificateAlias;
		this.certificatePassword = builder.certificatePassword;
		this.keystorePassword = builder.keystorePassword;
		this.keystoreOutputPath = builder.keystoreOutputPath;
		this.keystoreType = builder.keystoreType;
		this.certificate = builder.certificate;
		this.key = builder.key;
		this.logCat = new StringBuilder();
	}

	public void createNewKeystore(){
		try{
			this.keystore = java.security.KeyStore.getInstance(this.keystoreType);
			this.keystore.load(null, null);
			this.keystore.setKeyEntry(
				this.certificateAlias,
				this.key,
				this.certificatePassword.toCharArray(),
				new java.security.cert.Certificate[]{this.certificate}
			);
			this.keystore.store(new FileOutputStream(new File(this.keystoreOutputPath)), this.keystorePassword.toCharArray());
		}catch (KeyStoreException e){
			this.writeLogCat(e);
		}catch (IOException e){
			this.writeLogCat(e);
		}catch (NoSuchAlgorithmException e){
			this.writeLogCat(e);
		}catch (CertificateException e){
			this.writeLogCat(e);
		}
	}

	public String getLogCat(){
		return this.logCat.toString();
	}

	private final void writeLogCat(Exception e){
		this.logCat.append("Error Type : ");
		this.logCat.append(e.getClass().getSimpleName());
		this.logCat.append("\n");
		this.logCat.append("Error Message : ");
		this.logCat.append(e.toString());
		this.logCat.append("\n");
		this.logCat.append("-------------------------------------");
		this.logCat.append("\n\n");
	}

	public static class Builder{
		private String certificateAlias;
		private String certificatePassword;
		private String keystorePassword;
		private String keystoreOutputPath;
		private String keystoreType;
		private PrivateKey key;
		private X509Certificate certificate;

		public Builder setCertificateAlias(String alias){
			this.certificateAlias = alias;
			return this;
		}

		public Builder setCertificatePassword(String certPassword){
			this.certificatePassword = certPassword;
			return this;
		}

		public Builder setKeystorePassword(String keystorePassword){
			this.keystorePassword = keystorePassword;
			return this;
		}

		public Builder setOutputKeystore(String filePath){
			this.keystoreOutputPath = filePath;
			return this;
		}

		public Builder setKeystoreType(String type){
			this.keystoreType = type;
			return this;
		}

		public Builder setCertificateKeystore(X509Certificate cert){
			this.certificate = cert;
			return this;
		}

		public Builder setPrivateKey(PrivateKey key){
			this.key = key;
			return this;
		}

		public KeyStoreM build(){
			return new KeyStoreM(this);
		}
	}

	public static enum Type{
		AndroidCAStore("AndroidCAStore"),
		AndroidKeyStore("AndroidKeyStore"),
		BCPKCS12("BCPKCS12"),
		BKS("BKS"),
		BouncyCastle("BouncyCastle"),
		PKCS12("PKCS12"),
		PKCS12_DEF("PKCS12-DEF");

		private String type;

		private Type(String val){
			this.type = val;
		}

		@Override
		public String toString(){
			return this.type;
		}
	}
}
