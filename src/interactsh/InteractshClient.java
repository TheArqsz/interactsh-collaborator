package interactsh;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONArray;
import org.json.JSONObject;
import com.github.shamil.Xid;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import lombok.Getter;

public class InteractshClient {
	private PrivateKey privateKey;
	private PublicKey publicKey;

	@Getter
	private final String correlationId;
	private final String secretKey;
	private final String pubKeyBase64;

	private String host;
	private int port;
	private boolean scheme;
	@Getter
	private boolean registered;
	private String authorization;

	public InteractshClient() {
		this.correlationId = Xid.get().toString();
		this.secretKey = UUID.randomUUID().toString();

		KeyPair kp = generateKeys();
		this.publicKey = kp.getPublic();
		this.privateKey = kp.getPrivate();
		this.pubKeyBase64 =
				Base64.getEncoder().encodeToString(getPublicKey().getBytes(StandardCharsets.UTF_8));

		this.host = burp.gui.Config.getHost();
		this.scheme = burp.gui.Config.getScheme();
		this.authorization = burp.gui.Config.getAuth();
		try {
			this.port = Integer.parseInt(burp.gui.Config.getPort());
		} catch (NumberFormatException ne) {
			this.port = 443;
		}
	}

	public boolean register() {
		burp.BurpExtender.api.logging()
				.logToOutput("Registering correlation with ID: " + correlationId);
		try {
			JSONObject registerData = new JSONObject();
			registerData.put("public-key", pubKeyBase64);
			registerData.put("secret-key", secretKey);
			registerData.put("correlation-id", correlationId);

			String requestBody = registerData.toString();
			StringBuilder requestBuilder = new StringBuilder();

			requestBuilder.append("POST /register HTTP/1.1\r\n").append("Host: ").append(host)
					.append("\r\n").append("User-Agent: Interact.sh Client\r\n")
					.append("Content-Type: application/json\r\n").append("Content-Length: ")
					.append(requestBody.length()).append("\r\n");

			if (authorization != null && !authorization.isEmpty()) {
				requestBuilder.append("Authorization: ").append(authorization).append("\r\n");
			}

			requestBuilder.append("Connection: close\r\n\r\n").append(requestBody);

			String request = requestBuilder.toString();

			HttpService httpService = HttpService.httpService(host, port, scheme);
			HttpRequest httpRequest = HttpRequest.httpRequest(httpService, request);
			HttpResponse resp = burp.BurpExtender.api.http().sendRequest(httpRequest).response();

			if (resp.statusCode() == 200) {
				this.registered = true;
				burp.BurpExtender.api.logging().logToOutput("Session registration was successful.");
				return true;
			} else {
				burp.BurpExtender.api.logging().logToError(
						"Registration was unsuccessful. Status Code: " + resp.statusCode());
				burp.BurpExtender.api.logging()
						.logToError("Error message: \n\n" + resp.bodyToString());
			}
		} catch (Exception ex) {
			if (ex.getMessage() != null && ex.getMessage().contains("UnknownHostException")) {
				burp.BurpExtender.api.logging().logToError(
						"Registration failed - the host '" + host + "' could not be resolved.");
			} else {
				burp.BurpExtender.api.logging().logToError(ex.getMessage());
			}
		}
		return false;
	}

	public boolean poll() {
		StringBuilder requestBuilder = new StringBuilder();

		requestBuilder.append("GET /poll?id=").append(correlationId).append("&secret=")
				.append(secretKey).append(" HTTP/1.1\r\n").append("Host: ").append(host)
				.append("\r\n").append("User-Agent: Interact.sh Client\r\n");

		if (authorization != null && !authorization.isEmpty()) {
			requestBuilder.append("Authorization: ").append(authorization).append("\r\n");
		}

		requestBuilder.append("Connection: close\r\n\r\n");

		String request = requestBuilder.toString();

		HttpService httpService = HttpService.httpService(host, port, scheme);
		HttpRequest httpRequest = HttpRequest.httpRequest(httpService, request);
		HttpResponse resp = burp.BurpExtender.api.http().sendRequest(httpRequest).response();
		if (resp.statusCode() != 200) {
			burp.BurpExtender.api.logging().logToError("Session with correlation ID "
					+ correlationId + " was unsuccessful - status returned: " + resp.statusCode());
			return false;
		}

		String responseBody = resp.bodyToString();
		try {
			JSONObject jsonObject = new JSONObject(responseBody);
			String aesKey = jsonObject.getString("aes_key");
			String key = this.decryptAesKey(aesKey);

			if (!jsonObject.isNull("data")) {
				JSONArray data = jsonObject.getJSONArray("data");
				for (int i = 0; i < data.length(); i++) {
					String decryptedData = decryptData(data.getString(i), key);

					InteractshEntry entry = new InteractshEntry(decryptedData);
					burp.BurpExtender.addToTable(entry);
				}
			}
		} catch (Exception ex) {
			if (ex.getMessage() != null && ex.getMessage().contains("UnknownHostException")) {
				burp.BurpExtender.api.logging().logToError(
						"Polling failed - the host '" + host + "' could not be resolved.");
			} else {
				burp.BurpExtender.api.logging().logToError(ex.getMessage());
			}
		}
		return true;
	}

	public void deregister() {
		burp.BurpExtender.api.logging()
				.logToOutput("Deregistering correlation with ID: " + correlationId);
		try {
			JSONObject deregisterData = new JSONObject();
			deregisterData.put("correlation-id", correlationId);
			deregisterData.put("secret-key", secretKey);
			String requestBody = deregisterData.toString();

			StringBuilder requestBuilder = new StringBuilder();

			requestBuilder.append("POST /deregister HTTP/1.1\r\n").append("Host: ").append(host)
					.append("\r\nUser-Agent: Interact.sh Client\r\n")
					.append("Content-Type: application/json\r\n").append("Content-Length: ")
					.append(requestBody.length()).append("\r\n");

			if (authorization != null && !authorization.isEmpty()) {
				requestBuilder.append("Authorization: ").append(authorization).append("\r\n");
			}

			requestBuilder.append("Connection: close\r\n\r\n").append(requestBody);

			String request = requestBuilder.toString();

			HttpService httpService = HttpService.httpService(host, port, scheme);
			HttpRequest httpRequest = HttpRequest.httpRequest(httpService, request);
			burp.BurpExtender.api.http().sendRequest(httpRequest).response();
		} catch (Exception ex) {
			if (ex.getMessage() != null && ex.getMessage().contains("UnknownHostException")) {
				burp.BurpExtender.api.logging().logToError(
						"Deregister failed - the host '" + host + "' could not be resolved.");
			} else {
				burp.BurpExtender.api.logging().logToError(ex.getMessage());
			}
		}
	}

	public String getInteractDomain() {
		if (correlationId == null || correlationId.isEmpty()) {
			return "";
		} else {
			String fullDomain = correlationId;

			// Fix the string up to 33 characters
			Random random = new Random();
			while (fullDomain.length() < 33) {
				fullDomain += (char) (random.nextInt(26) + 'a');
			}

			fullDomain += "." + host;
			return fullDomain;
		}
	}

	private KeyPair generateKeys() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			return kpg.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			burp.BurpExtender.api.logging().logToError("Unable to generate client key pair", e);
			throw new RuntimeException(e);
		}
	}

	private String getPublicKey() {
		String pubKey = "-----BEGIN PUBLIC KEY-----\n";
		String[] chunks =
				splitStringEveryN(Base64.getEncoder().encodeToString(publicKey.getEncoded()), 64);
		for (String chunk : chunks) {
			pubKey += chunk + "\n";
		}
		pubKey += "-----END PUBLIC KEY-----\n";
		return pubKey;
	}

	private String decryptAesKey(String encrypted) throws Exception {
		byte[] cipherTextArray = Base64.getDecoder().decode(encrypted);

		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
		OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1",
				new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
		cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
		byte[] decrypted = cipher.doFinal(cipherTextArray);

		return new String(decrypted);
	}

	private static String decryptData(String input, String key) throws Exception {
		byte[] cipherTextArray = Base64.getDecoder().decode(input);
		byte[] iv = Arrays.copyOfRange(cipherTextArray, 0, 16);
		byte[] cipherText = Arrays.copyOfRange(cipherTextArray, 16, cipherTextArray.length - 1);

		IvParameterSpec ivSpec = new IvParameterSpec(iv);

		SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");
		Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
		byte[] decrypted = cipher.doFinal(cipherText);

		return new String(decrypted);
	}

	private String[] splitStringEveryN(String s, int interval) {
		int arrayLength = (int) Math.ceil(((s.length() / (double) interval)));
		String[] result = new String[arrayLength];

		int j = 0;
		int lastIndex = result.length - 1;
		for (int i = 0; i < lastIndex; i++) {
			result[i] = s.substring(j, j + interval);
			j += interval;
		}
		result[lastIndex] = s.substring(j);

		return result;
	}
}
