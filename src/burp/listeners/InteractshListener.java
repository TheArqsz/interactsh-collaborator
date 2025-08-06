package burp.listeners;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import interactsh.Client;

public class InteractshListener {
    private final ExecutorService executor;
    private volatile Client client;

    public InteractshListener() {
        this.executor = Executors.newSingleThreadExecutor();
        this.executor.submit(this::pollingLoop);
    }

    private void pollingLoop() {
        this.client = new Client();
        try {
            if (client.register()) {
                while (!Thread.currentThread().isInterrupted()) {
                    client.poll();
                    try {
                        long pollTime = burp.BurpExtender.getPollTime();
                        TimeUnit.SECONDS.sleep(pollTime);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt(); // Preserve interrupt status to exit loop
                    }
                }
            } else {
                burp.BurpExtender.api.logging().logToError("Unable to register interactsh client");
            }
        } catch (Exception ex) {
            burp.BurpExtender.api.logging().logToError(ex.getMessage());
        } finally {
            if (client != null && client.isRegistered()) {
                client.deregister();
            }
        }
    }

    public void close() {
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                burp.BurpExtender.api.logging().logToError("Polling task did not terminate in time.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void pollNowAll() {
        Client currentClient = this.client;
        if (currentClient != null && currentClient.isRegistered()) {
            executor.submit(currentClient::poll);
        }
    }

    public void generateCollaborator() {
        Client currentClient = this.client;
        if (currentClient != null) {
            String interactDomain = currentClient.getInteractDomain();
            burp.BurpExtender.api.logging().logToOutput("New domain is: " + interactDomain);
            StringSelection stringSelection = new StringSelection(interactDomain);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
        } else {
            burp.BurpExtender.api.logging().logToError("Interact.sh client is not yet initialized.");
        }
    }
}