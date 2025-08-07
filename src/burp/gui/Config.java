package burp.gui;

import burp.BurpExtender;
import burp.api.montoya.persistence.Preferences;

public class Config {

	private static final String DEFAULT_SERVER = "oast.pro";
	private static final String DEFAULT_PORT = "443";
	private static final String DEFAULT_AUTHORIZATION = "";
	private static final String DEFAULT_POLL_INTERVAL = "60";
	private static final String DEFAULT_USES_TLS = "true";

	private static Preferences preferences() {
		return BurpExtender.api.persistence().preferences();
	}

	private static String getString(String key, String defaultValue) {
		String value = preferences().getString(key);
		return (value == null) ? defaultValue : value;
	}

	public static void generateConfig() {
		if (preferences().getString("interactsh-server") == null) {
			preferences().setString("interactsh-server", DEFAULT_SERVER);
			preferences().setString("interactsh-port", DEFAULT_PORT);
			preferences().setString("interactsh-authorization", DEFAULT_AUTHORIZATION);
			preferences().setString("interactsh-poll-time", DEFAULT_POLL_INTERVAL);
			preferences().setString("interactsh-uses-tls", DEFAULT_USES_TLS);
		}
	}

	public static void loadConfig() {
		String server = getString("interactsh-server", DEFAULT_SERVER);
		String port = getString("interactsh-port", DEFAULT_PORT);
		String tls = getString("interactsh-uses-tls", DEFAULT_USES_TLS);
		String authorization = getString("interactsh-authorization", DEFAULT_AUTHORIZATION);
		String pollInterval = getString("interactsh-poll-time", DEFAULT_POLL_INTERVAL);

		InteractshTab.setServerText(server);
		InteractshTab.setPortText(port);
		InteractshTab.setAuthText(authorization);
		InteractshTab.setPollText(pollInterval);
		InteractshTab.setTlsBox(Boolean.parseBoolean(tls));
	}

	public static void updateConfig() {
		String server = InteractshTab.getServerText();
		String port = InteractshTab.getPortText();
		String authorization = InteractshTab.getAuthText();
		String pollInterval = InteractshTab.getPollText();
		String tls = InteractshTab.getTlsBox();

		preferences().setString("interactsh-server", server);
		preferences().setString("interactsh-port", port);
		preferences().setString("interactsh-uses-tls", tls);
		preferences().setString("interactsh-poll-time", pollInterval);
		preferences().setString("interactsh-authorization", authorization);
	}

	public static String getHost() {
		return getString("interactsh-server", DEFAULT_SERVER);
	}

	public static String getPort() {
		return getString("interactsh-port", DEFAULT_PORT);
	}

	public static boolean getScheme() {
		return Boolean.parseBoolean(getString("interactsh-uses-tls", DEFAULT_USES_TLS));
	}

	public static String getAuth() {
		return getString("interactsh-authorization", DEFAULT_AUTHORIZATION);
	}

	public static String getPollInterval() {
		return getString("interactsh-poll-time", DEFAULT_POLL_INTERVAL);
	}
}
