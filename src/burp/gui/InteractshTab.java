package burp.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.listeners.InteractshListener;
import interactsh.InteractEntry;
import layout.SpringUtilities;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import java.awt.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class InteractshTab extends JComponent {
    private final MontoyaApi api;

    private JTabbedPane mainPane;
    private JSplitPane splitPane;
    private JScrollPane scrollPane;
    private JSplitPane tableSplitPane;
    private JPanel resultsPanel;
    private JTextField pollField;
    private Table logTable;
    private final LogTable logTableModel;

    private static JTextField serverText;
    private static JTextField portText;
    private static JTextField authText;
    private static JTextField pollText;
    private static JCheckBox tlsBox;

    private final List<InteractEntry> log = new ArrayList<>();
    private InteractshListener listener;

    private HttpRequestEditor requestViewer; 
    private HttpResponseEditor responseViewer;

    private JPanel resultsCardPanel;
    private CardLayout resultsLayout;
    private JTextArea genericDetailsViewer;

    public InteractshTab(MontoyaApi api) {
        this.api = api;
        this.listener = new InteractshListener();

        setLayout(new BoxLayout(this, BoxLayout.PAGE_AXIS));

        mainPane = new JTabbedPane();
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainPane.addTab("Logs", splitPane);

        // HTTP/-s traffic viewer
        requestViewer = api.userInterface().createHttpRequestEditor();  
        responseViewer = api.userInterface().createHttpResponseEditor();
        JSplitPane viewersSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
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
        sortKeys.add(new RowSorter.SortKey(LogTable.Column.ID.ordinal(), SortOrder.ASCENDING));
        sorter.setSortKeys(sortKeys);

        sorter.setComparator(LogTable.Column.TYPE.ordinal(), Comparator.naturalOrder());
        sorter.setComparator(LogTable.Column.TIME.ordinal(), Comparator.naturalOrder());

        JTableHeader header = logTable.getTableHeader();
        ((DefaultTableCellRenderer) header.getDefaultRenderer()).setHorizontalAlignment(SwingConstants.LEFT);

        for (LogTable.Column col : LogTable.Column.values()) {
            TableColumn tableColumn = logTable.getColumnModel().getColumn(col.ordinal());
            tableColumn.setPreferredWidth(col.getPreferredWidth());
            if (col.getMaxWidth() != -1) {
                tableColumn.setMaxWidth(col.getMaxWidth());
            }
        }
        
        DefaultTableCellRenderer leftAlignRenderer = new DefaultTableCellRenderer();
        leftAlignRenderer.setHorizontalAlignment(SwingConstants.LEFT);
        logTable.getColumnModel().getColumn(LogTable.Column.ID.ordinal()).setCellRenderer(leftAlignRenderer);
        logTable.getColumnModel().getColumn(LogTable.Column.TIME.ordinal()).setCellRenderer(new InstantCellRenderer());

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
        JButton collaboratorButton = new JButton("Generate Interactsh URL");
        JButton refreshButton = new JButton("Refresh");
        JButton clearLogButton = new JButton("Clear log");
        JLabel pollLabel = new JLabel("Poll Time: ");
        pollField = new JTextField(Config.getPollInterval(), 4);
        pollField.setEditable(false);
        pollField.setOpaque(false);
        pollField.setBorder(null);
        pollField.setForeground(UIManager.getColor("Label.foreground"));

        collaboratorButton.addActionListener(e -> this.listener.generateCollaborator());
        refreshButton.addActionListener(e -> this.listener.pollNowAll());
        clearLogButton.addActionListener(e -> this.clearLog());

        controlsPanel.add(collaboratorButton);
        controlsPanel.add(pollLabel);
        controlsPanel.add(pollField);
        controlsPanel.add(refreshButton);
        controlsPanel.add(clearLogButton);

        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel filterLabel = new JLabel("Filter:");
        filterLabel.setEnabled(false);
        filterPanel.add(filterLabel);
        ButtonGroup filterGroup = new ButtonGroup();
        String[] protocols = {"All", "HTTP", "DNS", "SMTP"}; 

        for (String protocol : protocols) {
            JToggleButton filterButton = new JToggleButton(protocol);
            filterButton.addActionListener(e -> {
                String selectedProtocol = filterButton.getText();
                if ("All".equals(selectedProtocol)) {
                    sorter.setRowFilter(null);
                } else {
                    sorter.setRowFilter(RowFilter.regexFilter("(?i)" + selectedProtocol, LogTable.Column.TYPE.ordinal()));
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

        serverText = new JTextField("oast.pro", 20);
        portText = new JTextField("443", 20);
        authText = new JTextField("", 20);
        pollText = new JTextField("60", 20);
        tlsBox = new JCheckBox("", true);

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
            burp.gui.Config.updateConfig();
            pollField.setText(pollText.getText());
            listener.close();
            this.listener = new InteractshListener();
        });
        innerConfig.add(updateConfigButton);
        innerConfig.add(new JPanel());

        SpringUtilities.makeCompactGrid(innerConfig,
                6, 2, // rows, cols
                6, 6, // initX, initY
                6, 6); // xPad, yPad

        JPanel documentationPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel help = new JLabel(
                "Check out https://github.com/projectdiscovery/interactsh for an up to date list of public Interactsh servers",
                SwingConstants.LEFT);
        documentationPanel.setAlignmentY(Component.TOP_ALIGNMENT);
        documentationPanel.add(help);
        configPanel.add(documentationPanel);

        add(mainPane);
    }

    public InteractshListener getListener() { return this.listener; }
    public static String getServerText() { return serverText.getText(); }
    public static void setServerText(String t) { serverText.setText(t); }
    public static String getPortText() { return portText.getText(); }
    public static void setPortText(String text) { portText.setText(text); }
    public static String getAuthText() { return authText.getText(); }
    public static String getPollText() { return pollText.getText(); }
    public static void setAuthText(String text) { authText.setText(text); }
    public static void setPollText(String text) { pollText.setText(text); }
    public static String getTlsBox() { return Boolean.toString(tlsBox.isSelected()); }
    public static void setTlsBox(boolean value) { tlsBox.setSelected(value); }
    public JTextField getPollField() { return pollField; }

    public void addToTable(InteractEntry i) {
        SwingUtilities.invokeLater(() -> {
            synchronized (log) {
                log.add(i);
                int rowIndex = log.size() - 1;
                logTableModel.fireTableRowsInserted(rowIndex, rowIndex);
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
        }
    }

    //
    // extend JTable to handle cell selection
    //
    private class Table extends JTable {

        public Table(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            int modelRow = convertRowIndexToModel(row);
            if (modelRow == -1) {
                return;
            }

            InteractEntry selectedEntry = log.get(modelRow);

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

    private static class InstantCellRenderer extends DefaultTableCellRenderer {
        private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS z").withZone(ZoneId.systemDefault());

        public InstantCellRenderer() {
            setHorizontalAlignment(SwingConstants.LEFT);
        }

        @Override
        public void setValue(Object value) {
            if (value instanceof Instant) {
                value = FORMATTER.format((Instant) value);
            }
            super.setValue(value);
        }
    }

    //
    // implement AbstractTableModel
    //

    private class LogTable extends AbstractTableModel {
        public enum Column {
            ID("ID", Integer.class, 50, 80),
            ENTRY("Entry", String.class, 120, -1),
            TYPE("Type", String.class, 70, 100),
            SOURCE_IP("Source IP address", String.class, 120, -1),
            TIME("Time", Instant.class, 150, -1);

            private final String name;
            private final Class<?> type;
            private final int preferredWidth;
            private final int maxWidth;

            Column(String name, Class<?> type, int preferredWidth, int maxWidth) {
                this.name = name;
                this.type = type;
                this.preferredWidth = preferredWidth;
                this.maxWidth = maxWidth;
            }

            public String getName() { return name; }
            public Class<?> getType() { return type; }
            public int getPreferredWidth() { return preferredWidth; }
            public int getMaxWidth() { return maxWidth; }
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
            InteractEntry ie = log.get(rowIndex);

            switch (Column.values()[columnIndex]) {
                case ID:        return rowIndex + 1;
                case ENTRY:     return ie.uid;
                case TYPE:      return ie.protocol;
                case SOURCE_IP: return ie.address;
                case TIME:      return ie.timestamp;
                default:        return "";
            }
        }
    }

    public void cleanup() {
        listener.close();
    }
}