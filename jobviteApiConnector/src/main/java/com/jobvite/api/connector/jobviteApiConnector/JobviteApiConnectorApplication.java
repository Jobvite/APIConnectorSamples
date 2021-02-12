package com.jobvite.api.connector.jobviteApiConnector;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.MessageFormat;
import java.util.Base64;

@SpringBootApplication
public class JobviteApiConnectorApplication {
	static String jobvitePublicKeyPath= "replace with jobvite der format public key path";
	static String customerPrivateKeyPath= "replace with der format  private key path";
	static String apiKey="apiKey";
	static String apiSecret="secretkeyGoesHere";
	static String baseUrl="https://api.jobvite.com/api/v2/task?api={0}&sc={1}";
	/**
	 * User can use either pem format file or der format file. Below param is required only if user wants to use pem format file
	 * Also to use pem format file rathen than calling readPublicKeyFromDer call readPublicKeyFromPem method inside main method
	 */
	static String jobvitePemPublicKeyPath ="replace with pem format jobvite public key path";

	public static void main(String[] args) throws Exception {
		//Generate AES Key
		SecretKey aesKey = generateSecretKey();
		String jsonPayload = "{ \"filter\":{ \"task\":{ \"processInstanceId\":{ \"eq\":\"5fda297111edfb36b766c787\" } } } }";
		//Encrypt payload using AES key
		byte[] payLoad = encrypt(jsonPayload.getBytes() ,aesKey);

		PublicKey jobvitePublicKey = readPublicKeyFromDer();
		//Encrypt AES key using jobvite public key
		byte[] encryptedSecretKey = encrypt(aesKey.getEncoded(), jobvitePublicKey);

		String response = makePostCallToJobviteApi(encryptedSecretKey, payLoad);
		JSONObject  jsonObject = new JSONObject(response);
		decryptJobviteResponse(jsonObject.get("payload").toString(),jsonObject.get("key").toString());
		SpringApplication.run(JobviteApiConnectorApplication.class, args);
	}


	private static String makePostCallToJobviteApi(byte[] encryptedSecretKey,byte[] payLoad) throws IOException {
		URL url = new URL(MessageFormat.format(baseUrl, apiKey, apiSecret));
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("POST");
		con.setRequestProperty("Content-Type", "application/json; utf-8");
		con.setRequestProperty("Accept", "application/json");
		con.setDoOutput(true);
		String jsonInputString = "{\"key\": \"" + Base64.getEncoder().encodeToString(encryptedSecretKey) + "\", \"payload\": \"" + Base64.getEncoder().encodeToString(payLoad) + "\"}";
		try (OutputStream os = con.getOutputStream()) {
			byte[] input = jsonInputString.getBytes("utf-8");
			os.write(input, 0, input.length);
		}

		try (BufferedReader br = new BufferedReader(
				new InputStreamReader(con.getInputStream(), "utf-8"))) {
			StringBuilder response = new StringBuilder();
			String responseLine = null;
			while ((responseLine = br.readLine()) != null) {
				response.append(responseLine.trim());
			}
			return response.toString();

		}
	}

	private static  void decryptJobviteResponse(String payload, String key) throws GeneralSecurityException, IOException {
		PrivateKey privatekey = readPrivateKey();
		byte[] aesKey= decrypt(Base64.getDecoder().decode(key),privatekey);
		SecretKey secretKey= new SecretKeySpec(aesKey, "AES");
		byte[] response = decrypt(Base64.getDecoder().decode(payload),secretKey);
		System.out.println(new String(response));
	}

	public static RSAPublicKey readPublicKeyFromPem() throws Exception {
		File file = new File(jobvitePemPublicKeyPath);
		KeyFactory factory = KeyFactory.getInstance("RSA");

		try (FileReader keyReader = new FileReader(file);
			 PemReader pemReader = new PemReader(keyReader)) {

			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
			return (RSAPublicKey) factory.generatePublic(pubKeySpec);
		}
	}


	public  static  PublicKey readPublicKeyFromDer() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		Path path = Paths.get(jobvitePublicKeyPath);
		byte[] privKeyByteArray = Files.readAllBytes(path);

		X509EncodedKeySpec spec =
				new X509EncodedKeySpec(privKeyByteArray);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public  static  PrivateKey readPrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
		Path path = Paths.get(customerPrivateKeyPath);
		byte[] privKeyByteArray = Files.readAllBytes(path);

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return  privateKey;
	}


	public static final SecretKey generateSecretKey() throws GeneralSecurityException {
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(256);
		return kg.generateKey();
	}

	public static byte[] encrypt(byte[] plainBytes, SecretKey secretKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(plainBytes);
	}

	public static byte[] decrypt(byte[] cipherBytes, SecretKey secretKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		return cipher.doFinal(cipherBytes);
	}


	public static byte[] encrypt(byte[] plainBytes, PublicKey publicKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(plainBytes);
	}

	public static byte[] decrypt(byte[] cipherBytes, PrivateKey privateKey) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(cipherBytes);
	}
}
