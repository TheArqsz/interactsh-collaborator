package burp.listeners;

import interactsh.Client;

import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.swing.SwingUtilities;

public class InteractshListener {
    private final ExecutorService executor;
    private volatile Client client;
    private final Semaphore pollSignal = new Semaphore(0);


    public InteractshListener(Consumer<String> onReadyCallback) {
        this.executor = Executors.newSingleThreadExecutor();
        this.executor.submit(() -> pollingLoop(onReadyCallback));
    }

    private void pollingLoop(Consumer<String> onReadyCallback) {
        this.client = new Client();
        try {
            if (client.register()) {
                if (onReadyCallback != null) {
                    String newUrl = client.getInteractDomain();
                    SwingUtilities.invokeLater(() -> onReadyCallback.accept(newUrl));
                }
                while (!Thread.currentThread().isInterrupted()) {
                    client.poll();
                    try {
                        long pollTime = burp.BurpExtender.getPollTime();
                        pollSignal.tryAcquire(pollTime, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt(); 
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
            pollSignal.release();
        }
    }

    public void copyCurrentUrlToClipboard() {
        Client currentClient = this.client;
        if (currentClient != null) {
            String interactDomain = currentClient.getInteractDomain();
            burp.BurpExtender.api.logging().logToOutput("New domain in this session is: " + interactDomain);
            StringSelection stringSelection = new StringSelection(interactDomain);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, null);
            Toolkit.getDefaultToolkit().getSystemSelection().setContents(stringSelection, null);
        } else {
            burp.BurpExtender.api.logging().logToError("Interact.sh client is not yet initialized.");
        }
    }
}