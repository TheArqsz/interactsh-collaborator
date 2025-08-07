package burp.gui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Desktop;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.SpringLayout;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.listeners.InteractshListener;
import interactsh.InteractshEntry;
import layout.SpringUtilities;
import lombok.Getter;
import lombok.Setter;

public class InteractshTab extends JComponent {
	private final MontoyaApi api;

	private JTabbedPane mainPane;
	private JSplitPane splitPane;
	private JScrollPane scrollPane;
	private JSplitPane tableSplitPane;
	private JPanel resultsPanel;
	@Getter
	private JTextField pollField;

	private Table logTable;
	private final LogTable logTableModel;

	private static JTextField serverText;
	private static JTextField portText;
	private static JTextField authText;
	private static JTextField pollText;
	private static JCheckBox tlsBox;

	private final List<InteractshEntry> log = new ArrayList<>();
	private InteractshListener listener;

	private HttpRequestEditor requestViewer;
	private HttpResponseEditor responseViewer;

	private JPanel resultsCardPanel;
	private CardLayout resultsLayout;
	private JTextArea genericDetailsViewer;

	public InteractshTab(MontoyaApi api) {
		this.api = api;
		this.listener = new InteractshListener(null);

		setLayout(new BoxLayout(this, BoxLayout.PAGE_AXIS));

		mainPane = new JTabbedPane();
		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
		mainPane.addTab("Logs", splitPane);

		// HTTP/-s traffic viewer
		requestViewer = api.userInterface().createHttpRequestEditor();
		responseViewer = api.userInterface().createHttpResponseEditor();
		JSplitPane viewersSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
				requestViewer.uiComponent(), responseViewer.uiComponent());
		viewersSplitPane.setResizeWeight(0.5);

		// Generic viewer
		resultsPanel = new JPanel(new BorderLayout());
		genericDetailsViewer = new JTextArea();
		genericDetailsViewer.setEditable(false);
		genericDetailsViewer.setWrapStyleWord(true);
		genericDetailsViewer.setLineWrap(true);
		resultsPanel.add(new JScrollPane(genericDetailsViewer), BorderLayout.CENTER);

		resultsLayout = new CardLayout();
		resultsCardPanel = new JPanel(resultsLayout);
		resultsCardPanel.add(resultsPanel, "GENERIC_VIEW");
		resultsCardPanel.add(viewersSplitPane, "HTTP_VIEW");

		logTableModel = new LogTable();
		logTable = new Table(logTableModel);
		tableSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

		TableRowSorter<TableModel> sorter = new TableRowSorter<>(logTableModel);
		logTable.setRowSorter(sorter);

		List<RowSorter.SortKey> sortKeys = new ArrayList<>();
		sortKeys.add(new RowSorter.SortKey(LogTable.Column.ID.ordinal(), SortOrder.DESCENDING));
		sorter.setSortKeys(sortKeys);

		sorter.setComparator(LogTable.Column.TYPE.ordinal(), Comparator.naturalOrder());
		sorter.setComparator(LogTable.Column.TIME.ordinal(), Comparator.naturalOrder());

		JTableHeader header = logTable.getTableHeader();
		((DefaultTableCellRenderer) header.getDefaultRenderer())
				.setHorizontalAlignment(SwingConstants.LEFT);

		for (LogTable.Column col : LogTable.Column.values()) {
			TableColumn tableColumn = logTable.getColumnModel().getColumn(col.ordinal());
			tableColumn.setPreferredWidth(col.getPreferredWidth());
			if (col.getMaxWidth() != -1) {
				tableColumn.setMaxWidth(col.getMaxWidth());
			}
		}

		LogTableCellRenderer renderer = new LogTableCellRenderer();
		for (int i = 0; i < logTable.getColumnCount(); i++) {
			logTable.getColumnModel().getColumn(i).setCellRenderer(renderer);
		}

		logTable.setRowSelectionAllowed(true);
		logTable.setColumnSelectionAllowed(true);
		scrollPane = new JScrollPane(logTable);

		tableSplitPane.setTopComponent(scrollPane);
		tableSplitPane.setBottomComponent(resultsCardPanel);
		splitPane.setBottomComponent(tableSplitPane);

		JPanel mainTopPanel = new JPanel();
		mainTopPanel.setLayout(new BoxLayout(mainTopPanel, BoxLayout.Y_AXIS));
		mainTopPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

		JPanel controlsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JButton generateUrlButton = new JButton("Regenerate Interactsh Session");
		JButton copyUrlButton = new JButton("Copy URL to clipboard");
		JButton refreshButton = new JButton("Refresh");
		JButton clearLogButton = new JButton("Clear log");
		JLabel pollLabel = new JLabel("Poll Time: ");
		pollField = new JTextField(Config.getPollInterval(), 4);
		pollField.setEditable(false);
		pollField.setOpaque(false);
		pollField.setBorder(null);
		pollField.setForeground(UIManager.getColor("Label.foreground"));

		copyUrlButton.setBackground(new Color(216, 102, 51));
		copyUrlButton.setForeground(Color.WHITE);
		copyUrlButton.setOpaque(true);
		copyUrlButton.setFont(copyUrlButton.getFont().deriveFont(Font.BOLD));
		copyUrlButton.setBorderPainted(false);

		generateUrlButton.addActionListener(e -> {
			listener.close();
			listener = new InteractshListener(newUrl -> {
				StringSelection stringSelection = new StringSelection(newUrl);
				try {
					Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection,
							null);
					Toolkit.getDefaultToolkit().getSystemSelection().setContents(stringSelection,
							null);
				} catch (Exception ex) {
					api.logging().logToError("Clipboard issue: " + ex.getMessage());
				}
				api.logging().logToOutput("Generated and copied new Interact.sh URL: " + newUrl);
			});
		});
		copyUrlButton.addActionListener(e -> this.listener.copyCurrentUrlToClipboard());
		refreshButton.addActionListener(e -> this.listener.pollNowAll());
		clearLogButton.addActionListener(e -> this.clearLog());

		controlsPanel.add(generateUrlButton);
		controlsPanel.add(Box.createHorizontalStrut(3));
		controlsPanel.add(copyUrlButton);
		controlsPanel.add(Box.createHorizontalStrut(15));
		controlsPanel.add(refreshButton);
		controlsPanel.add(Box.createHorizontalStrut(3));
		controlsPanel.add(clearLogButton);
		controlsPanel.add(Box.createHorizontalStrut(20));
		controlsPanel.add(pollLabel);
		controlsPanel.add(pollField);

		JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JLabel filterLabel = new JLabel("Filter:");
		filterLabel.setEnabled(false);
		filterPanel.add(filterLabel);
		ButtonGroup filterGroup = new ButtonGroup();
		String[] protocols = {"All", "HTTP", "DNS", "SMTP", "LDAP", "SMB", "FTP"};

		for (String protocol : protocols) {
			JToggleButton filterButton = new JToggleButton(protocol);
			filterButton.addActionListener(e -> {
				String selectedProtocol = filterButton.getText();
				if ("All".equals(selectedProtocol)) {
					sorter.setRowFilter(null);
				} else {
					sorter.setRowFilter(RowFilter.regexFilter("(?i)" + selectedProtocol,
							LogTable.Column.TYPE.ordinal()));
				}
			});

			filterGroup.add(filterButton);
			filterPanel.add(filterButton);

			if ("All".equals(protocol)) {
				filterButton.setSelected(true);
			}
		}

		mainTopPanel.add(controlsPanel);
		mainTopPanel.add(filterPanel);
		splitPane.setTopComponent(mainTopPanel);

		// Configuration pane
		JPanel configPanel = new JPanel();
		configPanel.setLayout(new BoxLayout(configPanel, BoxLayout.Y_AXIS));
		JPanel subConfigPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		mainPane.addTab("Configuration", configPanel);
		configPanel.add(subConfigPanel);
		JPanel innerConfig = new JPanel();
		subConfigPanel.setMaximumSize(new Dimension(configPanel.getMaximumSize().width, 250));
		innerConfig.setLayout(new SpringLayout());
		subConfigPanel.add(innerConfig);

		serverText = new JTextField(Config.getHost(), 20);
		portText = new JTextField(Config.getPort(), 20);
		authText = new JTextField(Config.getAuth(), 20);
		pollText = new JTextField(Config.getPollInterval(), 20);
		tlsBox = new JCheckBox("", true);
		tlsBox.setSelected(Config.getScheme());

		innerConfig.add(new JLabel("Server: ", SwingConstants.TRAILING));
		innerConfig.add(serverText);
		innerConfig.add(new JLabel("Port: ", SwingConstants.TRAILING));
		innerConfig.add(portText);
		innerConfig.add(new JLabel("Authorization: ", SwingConstants.TRAILING));
		innerConfig.add(authText);
		innerConfig.add(new JLabel("Poll Interval (sec): ", SwingConstants.TRAILING));
		innerConfig.add(pollText);
		innerConfig.add(new JLabel("TLS: ", SwingConstants.TRAILING));
		innerConfig.add(tlsBox);

		JButton updateConfigButton = new JButton("Update Settings");
		updateConfigButton.addActionListener(e -> {
			String oldServer = burp.gui.Config.getHost();
			String oldPort = burp.gui.Config.getPort();
			String oldAuth = burp.gui.Config.getAuth();
			Boolean oldTls = burp.gui.Config.getScheme();

			String newServer = serverText.getText();
			String newPort = portText.getText();
			String newAuth = authText.getText();
			Boolean newTls = tlsBox.isSelected();

			burp.gui.Config.updateConfig();
			pollField.setText(pollText.getText());

			boolean criticalSettingChanged = !oldServer.equals(newServer)
					|| !oldPort.equals(newPort) || !oldAuth.equals(newAuth) || oldTls != newTls;

			if (criticalSettingChanged) {
				api.logging().logToOutput(
						"Server configuration changed. Creating new Interact.sh session.");
				if (listener != null) {
					listener.close();
				}
				this.listener.close();
				this.listener = new InteractshListener(null);
			} else {
				api.logging().logToOutput("Poll interval updated. Triggering immediate poll.");
				if (listener != null) {
					listener.pollNowAll();
				}
			}
		});
		innerConfig.add(updateConfigButton);
		innerConfig.add(new JPanel());

		SpringUtilities.makeCompactGrid(innerConfig, 6, 2, // rows, cols
				6, 6, // initX, initY
				6, 6); // xPad, yPad

		JPanel documentationPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

		String documentationUrl =
				"https://github.com/projectdiscovery/interactsh?tab=readme-ov-file#using-self-hosted-server";
		String linkHtml = "<html><b>View <a href=\"" + documentationUrl
				+ "\">the list of public Interactsh servers</a> on ProjectDiscovery's GitHub</b></html>";

		JEditorPane helpLink = createClickableLink(linkHtml);
		documentationPanel.setAlignmentY(Component.TOP_ALIGNMENT);
		documentationPanel.add(helpLink);
		configPanel.add(documentationPanel);

		add(mainPane);
	}

	public InteractshListener getListener() {
		return this.listener;
	}

	public static String getServerText() {
		return serverText.getText();
	}

	public static void setServerText(String t) {
		serverText.setText(t);
	}

	public static String getPortText() {
		return portText.getText();
	}

	public static void setPortText(String text) {
		portText.setText(text);
	}

	public static String getAuthText() {
		return authText.getText();
	}

	public static String getPollText() {
		return pollText.getText();
	}

	public static void setAuthText(String text) {
		authText.setText(text);
	}

	public static void setPollText(String text) {
		pollText.setText(text);
	}

	public static String getTlsBox() {
		return Boolean.toString(tlsBox.isSelected());
	}

	public static void setTlsBox(boolean value) {
		tlsBox.setSelected(value);
	}

	private JEditorPane createClickableLink(String html) {
		JEditorPane editorPane = new JEditorPane("text/html", html);
		editorPane.setEditable(false);
		editorPane.setOpaque(false);
		editorPane.setHighlighter(null);

		editorPane.addHyperlinkListener(e -> {
			if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
				if (Desktop.isDesktopSupported()
						&& Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
					try {
						Desktop.getDesktop().browse(e.getURL().toURI());
					} catch (IOException | URISyntaxException ex) {
						api.logging().logToError(ex);
					}
				} else {
					String url = e.getURL().toString();
					StringSelection stringSelection = new StringSelection(url);
					try {
						Toolkit.getDefaultToolkit().getSystemClipboard()
								.setContents(stringSelection, null);
						Toolkit.getDefaultToolkit().getSystemSelection()
								.setContents(stringSelection, null);
					} catch (Exception ex) {
						api.logging().logToError("Clipboard issue: " + ex.getMessage());
					}
					api.logging().logToOutput(
							"Desktop browse is not supported. URL copied to clipboard: " + url);
				}
			}
		});
		return editorPane;
	}

	private void updateUnreadCount() {
		Container parent = getParent();
		if (parent instanceof JTabbedPane tabbedPane) {
			int tabIndex = tabbedPane.indexOfComponent(this);
			if (tabIndex != -1) {
				long unreadCount = log.stream().filter(e -> !e.isRead()).count();
				String newTitle = "Interactsh";
				if (unreadCount > 0) {
					newTitle += " (" + unreadCount + ")";
				}
				tabbedPane.setTitleAt(tabIndex, newTitle);
			}
		}
	}

	public void addToTable(InteractshEntry i) {
		SwingUtilities.invokeLater(() -> {
			synchronized (log) {
				log.add(i);
				int rowIndex = log.size() - 1;
				logTableModel.fireTableRowsInserted(rowIndex, rowIndex);
				updateUnreadCount();
			}
		});
	}

	private void clearLog() {
		synchronized (log) {
			log.clear();
			requestViewer.setRequest(null);
			responseViewer.setResponse(null);
			genericDetailsViewer.setText("");
			logTableModel.fireTableDataChanged();
			updateUnreadCount();
		}
	}

	private class Table extends JTable {

		public Table(TableModel tableModel) {
			super(tableModel);
		}

		@Override
		public void changeSelection(int row, int col, boolean toggle, boolean extend) {
			super.changeSelection(row, col, toggle, extend);

			int modelRow = convertRowIndexToModel(row);
			if (modelRow == -1) {
				return;
			}

			InteractshEntry selectedEntry = log.get(modelRow);

			if (!selectedEntry.isRead()) {
				selectedEntry.setRead(true);
				logTableModel.fireTableRowsUpdated(modelRow, modelRow);
				updateUnreadCount();
			}

			if (selectedEntry.protocol.equals("http") || selectedEntry.protocol.equals("https")) {
				resultsLayout.show(resultsCardPanel, "HTTP_VIEW");
				if (selectedEntry.httpRequest != null) {
					requestViewer.setRequest(selectedEntry.httpRequest);
					responseViewer.setResponse(selectedEntry.httpResponse);
				} else {
					resultsLayout.show(resultsCardPanel, "GENERIC_VIEW");
					genericDetailsViewer.setText(selectedEntry.details);
					genericDetailsViewer.setCaretPosition(0);
				}
			} else {
				resultsLayout.show(resultsCardPanel, "GENERIC_VIEW");
				genericDetailsViewer.setText(selectedEntry.details);
				genericDetailsViewer.setCaretPosition(0);
			}

			super.changeSelection(row, col, toggle, extend);
		}
	}

	private class LogTableCellRenderer extends DefaultTableCellRenderer {
		private static final DateTimeFormatter FORMATTER = DateTimeFormatter
				.ofPattern("yyyy-MM-dd HH:mm:ss.SSS z").withZone(ZoneId.systemDefault());

		private final Font plainFont;
		private final Font boldFont;

		public LogTableCellRenderer() {
			Font originalFont = getFont();
			this.plainFont = originalFont.deriveFont(Font.PLAIN);
			this.boldFont = originalFont.deriveFont(Font.BOLD);
		}

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean isSelected, boolean hasFocus, int row, int column) {
			final Component c = super.getTableCellRendererComponent(table, value, isSelected,
					hasFocus, row, column);

			if (value instanceof Instant) {
				setText(FORMATTER.format((Instant) value));
			} else {
				setText(value == null ? "" : value.toString());
			}

			if (!isSelected) {
				int modelRow = table.convertRowIndexToModel(row);
				InteractshEntry entry = log.get(modelRow);
				c.setFont(entry.isRead() ? plainFont : boldFont);
			}

			setHorizontalAlignment(SwingConstants.LEFT);

			return c;
		}
	}

	private class LogTable extends AbstractTableModel {
		public enum Column {
			ID("ID", Integer.class, 50, 80), ENTRY("Entry", String.class, 120, -1), TYPE("Type",
					String.class, 70, 100), SOURCE_IP("Source IP address", String.class, 120,
							-1), TIME("Time", Instant.class, 150, -1);

			@Getter
			private final String name;
			@Getter
			private final Class<?> type;
			@Getter
			private final int preferredWidth;
			@Getter
			private final int maxWidth;

			Column(String name, Class<?> type, int preferredWidth, int maxWidth) {
				this.name = name;
				this.type = type;
				this.preferredWidth = preferredWidth;
				this.maxWidth = maxWidth;
			}
		}

		@Override
		public int getRowCount() {
			return log.size();
		}

		@Override
		public int getColumnCount() {
			return Column.values().length;
		}

		@Override
		public String getColumnName(int columnIndex) {
			return Column.values()[columnIndex].getName();
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return Column.values()[columnIndex].getType();
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			InteractshEntry ie = log.get(rowIndex);

			switch (Column.values()[columnIndex]) {
				case ID:
					return rowIndex + 1;
				case ENTRY:
					return ie.uid;
				case TYPE:
					return ie.protocol;
				case SOURCE_IP:
					return ie.address;
				case TIME:
					return ie.timestamp;
				default:
					return "";
			}
		}
	}

	public void cleanup() {
		listener.close();
	}
}
