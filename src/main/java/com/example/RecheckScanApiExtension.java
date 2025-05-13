package com.example;

import com.example.SettingsPanel;
import burp.api.montoya.*;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Clipboard;
import java.awt.event.*;
import java.io.*;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;

public class RecheckScanApiExtension implements BurpExtension, ExtensionUnloadingHandler {
    private MontoyaApi api;
    private String savedExtensions;
    private String savedOutputPath;
    private DefaultTableModel tableModel;
    private final Set<String> loggedRequests = new HashSet<>();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Recheck Scan API");
        api.extension().registerUnloadingHandler(this);
        loadSavedSettings();
        SwingUtilities.invokeLater(this::createUI);

        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                return RequestToBeSentAction.continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                HttpRequest request = response.initiatingRequest();
                int statusCode = response.statusCode();
                String method = request.method();

                if (statusCode >= 400 || method.equals("OPTIONS")) return ResponseReceivedAction.continueWith(response);
                ToolType sourceType = response.toolSource().toolType();
                if (sourceType == ToolType.EXTENSIONS) return ResponseReceivedAction.continueWith(response);

                boolean isScanner = sourceType == ToolType.SCANNER;
                String host = request.httpService().host();
                String path = request.pathWithoutQuery();
                String uniqueKey = host + "|" + path;

                if (api.scope().isInScope(request.url()) && !isExcluded(path)) {
                    SwingUtilities.invokeLater(() -> {
                        Boolean scanned = isScanner;
                        Boolean rejected = false;

                        for (int i = 0; i < tableModel.getRowCount(); i++) {
                            String existingHost = tableModel.getValueAt(i, 1).toString();
                            String existingPath = tableModel.getValueAt(i, 2).toString();
                            if (host.equals(existingHost) && path.equals(existingPath)) {
                                scanned = scanned || Boolean.TRUE.equals(tableModel.getValueAt(i, 3));
                                rejected = Boolean.TRUE.equals(tableModel.getValueAt(i, 4));
                                tableModel.removeRow(i);
                                break;
                            }
                        }

                        if (!scanned && !rejected) {
                            tableModel.insertRow(0, new Object[]{method, host, path, scanned, rejected});
                        } else {
                            tableModel.addRow(new Object[]{method, host, path, scanned, rejected});
                        }

                        loggedRequests.add(uniqueKey);
                        saveTableData();
                    });
                }
                return ResponseReceivedAction.continueWith(response);
            }
        });
    }

    private void createUI() {
        tableModel = new DefaultTableModel(new Object[]{"Method", "Host", "Path", "Scanned", "Rejected"}, 0) {
            @Override public boolean isCellEditable(int row, int column) {
                return column == 2 || column == 3 || column == 4;
            }
            @Override public Class<?> getColumnClass(int columnIndex) {
                return (columnIndex == 3 || columnIndex == 4) ? Boolean.class : String.class;
            }
        };

        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setDefaultRenderer(Boolean.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JCheckBox checkBox = new JCheckBox();
                checkBox.setSelected(Boolean.TRUE.equals(value));
                checkBox.setHorizontalAlignment(SwingConstants.CENTER);
                checkBox.setOpaque(true);
                checkBox.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
                return checkBox;
            }
        });

        table.getInputMap().put(KeyStroke.getKeyStroke("ctrl C"), "copyPath");
        table.getActionMap().put("copyPath", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int row = table.getSelectedRow();
                if (row >= 0) {
                    int modelRow = table.convertRowIndexToModel(row);
                    String pathValue = tableModel.getValueAt(modelRow, 2).toString();
                    StringSelection selection = new StringSelection(pathValue);
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
                }
            }
        });

        loadLogData();

        table.getModel().addTableModelListener(e -> {
            int row = e.getFirstRow();
            int col = e.getColumn();
            if (col == 3 || col == 4) {
                Boolean scanned = (Boolean) table.getValueAt(row, 3);
                Boolean rejected = (Boolean) table.getValueAt(row, 4);
                if (col == 3 && Boolean.TRUE.equals(scanned)) table.setValueAt(false, row, 4);
                else if (col == 4 && Boolean.TRUE.equals(rejected)) table.setValueAt(false, row, 3);
                saveTableData();
            }
        });

        JTextField searchField = new JTextField();
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchField.setPreferredSize(new Dimension(400, 28));
        searchPanel.add(new JLabel("Search path:"));
        searchPanel.add(searchField);

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        for (int i = 0; i < 5; i++) sorter.setSortable(i, false);
        table.setRowSorter(sorter);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            private void filter() {
                String keyword = searchField.getText().trim();
                sorter.setRowFilter(keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2));
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        JPanel logPanel = new JPanel(new BorderLayout());
        table.getTableHeader().setReorderingAllowed(false);
        logPanel.add(searchPanel, BorderLayout.NORTH);
        logPanel.add(scrollPane, BorderLayout.CENTER);

        JTextArea extensionArea = new JTextArea(savedExtensions != null ? savedExtensions : ".js, .css, .svg");
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                outputPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });

        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            savedExtensions = extensionArea.getText().trim();
            savedOutputPath = outputPathField.getText().trim();
            try {
                File configFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api.txt");
                if (!configFile.getParentFile().exists()) configFile.getParentFile().mkdirs();
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(configFile))) {
                    writer.write(savedExtensions + "\n" + savedOutputPath);
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(null, "Failed to save settings: " + ex.getMessage());
            }
            tableModel.setRowCount(0);
            loggedRequests.clear();
            loadLogData();
            JOptionPane.showMessageDialog(null, "Settings saved and project loaded.");
        });

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Logs", logPanel);
        tabs.addTab("Settings", SettingsPanel.create(extensionArea, outputPathField, browseButton, applyButton));

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);
    }

    private void loadSavedSettings() {
        try {
            File configFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api.txt");
            if (configFile.exists()) {
                List<String> lines = Files.readAllLines(configFile.toPath());
                if (lines.size() >= 2) {
                    savedExtensions = lines.get(0).trim();
                    savedOutputPath = lines.get(1).trim();
                }
            }
        } catch (IOException e) {
            api.logging().logToError("Failed to load settings: " + e.getMessage());
        }
    }

    private void loadLogData() {
        File logFile = getLogFile();
        if (logFile.exists()) {
            try {
                List<String> lines = Files.readAllLines(logFile.toPath());
                for (String line : lines) {
                    String[] parts = line.split(",", 5);
                    if (parts.length == 5) {
                        tableModel.insertRow(0, new Object[]{parts[0], parts[1], parts[2], Boolean.parseBoolean(parts[3]), Boolean.parseBoolean(parts[4])});
                        loggedRequests.add(parts[1] + "|" + parts[2]);
                    }
                }
            } catch (IOException e) {
                api.logging().logToError("Failed to load log: " + e.getMessage());
            }
        }
    }

    private File getLogFile() {
        File defaultLogFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api_log.csv");
        return (savedOutputPath != null && !savedOutputPath.isBlank())
                ? new File(savedOutputPath)
                : defaultLogFile;
    }

    private boolean isExcluded(String path) {
        if (savedExtensions == null || savedExtensions.isBlank()) return false;
        return Arrays.stream(savedExtensions.split(","))
                .map(String::trim)
                .anyMatch(path.toLowerCase()::endsWith);
    }

    private void saveTableData() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(getLogFile(), false))) {
            for (int i = tableModel.getRowCount() - 1; i >= 0; i--) {
                writer.write(String.join(",",
                        tableModel.getValueAt(i, 0).toString(),
                        tableModel.getValueAt(i, 1).toString(),
                        tableModel.getValueAt(i, 2).toString(),
                        String.valueOf(tableModel.getValueAt(i, 3)),
                        String.valueOf(tableModel.getValueAt(i, 4))));
                writer.newLine();
            }
        } catch (IOException e) {
            api.logging().logToError("Failed to save log: " + e.getMessage());
        }
    }

    @Override
    public void extensionUnloaded() {
        saveTableData();
    }
}
