package br.mp.mppa.rubrica.assinador;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Scanner;

import org.demoiselle.signer.core.CertificateLoader;
import org.demoiselle.signer.core.CertificateLoaderImpl;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS7Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;

public class Assinador {
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		Assinador assinador = new Assinador();
	
		KeyStore keyStore = readKeyStore();
		assinador.assinarArquivo( listarCertificados( keyStore ), readContent("C:\\desenv\\arquivo.pdf") );
	}
	
	private static String listarCertificados( KeyStore keyStore ) {
		Scanner scanner = new Scanner( System.in );
		
		HashMap<Integer, String> lista = new HashMap<Integer, String>();
		
		lista.put(1, "Certificado 1");
		lista.put(2, "Certificado 2");
		lista.put(3, "Certificado 3");
		
		System.out.println( "(1) - Certificado 1" );
		System.out.println( "(2) - Certificado 2" );
		System.out.println( "(3) - Certificado 3" );
		
		Integer key = Integer.parseInt( scanner.nextLine() );
		scanner.close();
		return lista.get( key );
	}

	private static KeyStore readKeyStore() {
		KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		KeyStore keyStore = keyStoreLoader.getKeyStore( );
		return keyStore;
	}

	public void assinarArquivo( String alias, byte[] content ) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		/* Gerando o HASH */
		java.security.MessageDigest md = 
				java.security.MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
		byte[] hash = md.digest( content );
		
		/* Gerando a assinatura a partir do HASH gerado anteriormente */		
		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
//		signer.setCertificate( getCertificate() );
		signer.setPrivateKey( getPrivateKey() );
		signer.setSignaturePolicy(PolicyFactory.Policies.AD_RB_CADES_2_2);
		byte[] signature = signer.doHashSign(hash);
	}

	private PrivateKey getPrivateKey() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		KeyStore keyStore = keyStoreLoader.getKeyStore( );
		String certificateAlias = keyStore.aliases().nextElement();
		PrivateKey chavePrivada = (PrivateKey)keyStore.getKey(certificateAlias, "pinnumber".toCharArray());
		return chavePrivada;
	}

	private X509Certificate getCertificate() {
		KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		KeyStore keyStore = keyStoreLoader.getKeyStore();
		CertificateLoader certificateLoader = new CertificateLoaderImpl();
		certificateLoader.setKeyStore(keyStore);
		return certificateLoader.loadFromToken();
	}
	
	private X509Certificate getCertificateChain() {
		KeyStoreLoader keyStoreLoader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		KeyStore keyStore = keyStoreLoader.getKeyStore();
		CertificateLoader certificateLoader = new CertificateLoaderImpl();
		certificateLoader.setKeyStore(keyStore);
		return certificateLoader.loadFromToken();
	}

	private static byte[] readContent( String filePath ) throws IOException {
		byte[] result = null;
		File file = new File( filePath );
		FileInputStream is = new FileInputStream(file);
		result = new byte[(int) file.length()];
		is.read(result);
		is.close();
		return result;
	}
}
