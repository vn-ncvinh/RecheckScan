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
import java.io.*;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;
import java.util.ArrayList;

public class RecheckScanApiExtension implements BurpExtension, ExtensionUnloadingHandler {
    private MontoyaApi api;
    private String savedExtensions;
    private String savedOutputPath;
    private DefaultTableModel tableModel;
    private final Set<String> loggedRequests = new HashSet<>();
    private final Map<String, Set<String>> pathToParams = new HashMap<>();

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
                String method = request.method();

                if (method.equals("OPTIONS")) return ResponseReceivedAction.continueWith(response);
                ToolType sourceType = response.toolSource().toolType();
                if (sourceType == ToolType.EXTENSIONS) return ResponseReceivedAction.continueWith(response);

                boolean isScanner = sourceType == ToolType.SCANNER;
                String host = request.httpService().host();
                String path = request.pathWithoutQuery();
                String uniqueKey = host + "|" + path;

                if (isScanner) {
                    SwingUtilities.invokeLater(() -> {
                        for (int i = 0; i < tableModel.getRowCount(); i++) {
                            String existingHost = tableModel.getValueAt(i, 1).toString();
                            String existingPath = tableModel.getValueAt(i, 2).toString();
                            if (host.equals(existingHost) && path.equals(existingPath)) {
                                tableModel.setValueAt(true, i, 4); // Mark as scanned
                                saveTableData();
                                break;
                            }
                        }
                    });
                    return ResponseReceivedAction.continueWith(response);
                }

                if (api.scope().isInScope(request.url()) && !isExcluded(path)) {
                    String query = request.query();
                    Set<String> newParams = new HashSet<>();
                    if (query != null && !query.isBlank()) {
                        for (String pair : query.split("&")) {
                            String[] kv = pair.split("=", 2);
                            if (kv.length > 0) newParams.add(kv[0].trim());
                        }
                    }

                    Set<String> knownParams = pathToParams.getOrDefault(uniqueKey, new HashSet<>());
                    Set<String> addedParams = new HashSet<>(newParams);
                    addedParams.removeAll(knownParams);
                    knownParams.addAll(newParams);
                    pathToParams.put(uniqueKey, knownParams);

                    String savedNote = String.join("|", knownParams);
                    String displayNote = String.join(", ", knownParams);
                    if (!addedParams.isEmpty()) {
                        displayNote += " [new: " + String.join(", ", addedParams) + "]";
                    }

                    final String finalDisplayNote = displayNote;
                    final String finalSavedNote = savedNote;

                    SwingUtilities.invokeLater(() -> {
                        Boolean scanned = isScanner;
                        Boolean rejected = false;
                        boolean found = false;
                        for (int i = 0; i < tableModel.getRowCount(); i++) {
                            String existingHost = tableModel.getValueAt(i, 1).toString();
                            String existingPath = tableModel.getValueAt(i, 2).toString();
                            if (host.equals(existingHost) && path.equals(existingPath)) {
                                scanned = scanned || Boolean.TRUE.equals(tableModel.getValueAt(i, 4));
                                rejected = Boolean.TRUE.equals(tableModel.getValueAt(i, 5));
                                tableModel.setValueAt(finalDisplayNote, i, 3);
                                tableModel.setValueAt(scanned, i, 4);
                                found = true;
                                break;
                            }
                        }
//                        if (!found) {
//                            tableModel.insertRow(0, new Object[]{method, host, path, finalDisplayNote, scanned, rejected});
//                        }
                        if (!found) {
                            Object[] newRow = new Object[]{method, host, path, finalDisplayNote, scanned, rejected};
                            int insertIndex = 0;
                            for (int i = 0; i < tableModel.getRowCount(); i++) {
                                boolean rowScanned = Boolean.TRUE.equals(tableModel.getValueAt(i, 4));
                                boolean rowRejected = Boolean.TRUE.equals(tableModel.getValueAt(i, 5));
                                if (rowScanned || rowRejected) {
                                    continue; // ưu tiên dòng chưa xử lý
                                }
                                insertIndex = i;
                                break;
                            }
                            tableModel.insertRow(insertIndex, newRow);
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
        tableModel = new DefaultTableModel(new Object[]{"Method", "Host", "Path", "Note", "Scanned", "Rejected"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 2 || column == 4 || column == 5;
            }
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return (columnIndex == 4 || columnIndex == 5) ? Boolean.class : String.class;
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

        table.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == 3 && value != null && value.toString().contains("[new:")) {
                    c.setForeground(Color.RED);
                } else {
                    c.setForeground(table.getForeground());
                }
                return c;
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.add(scrollPane, BorderLayout.CENTER);

        JTextField searchField = new JTextField();
        searchField.setPreferredSize(new Dimension(400, 28));
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchPanel.add(new JLabel("Search path:"));
        searchPanel.add(searchField);
        logPanel.add(searchPanel, BorderLayout.NORTH);

        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
        for (int i = 0; i < tableModel.getColumnCount(); i++) sorter.setSortable(i, false);
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

        loadLogData();

        table.getModel().addTableModelListener(e -> {
            int row = e.getFirstRow();
            int col = e.getColumn();
            if (col == 4 || col == 5) {
                Boolean scanned = (Boolean) table.getValueAt(row, 4);
                Boolean rejected = (Boolean) table.getValueAt(row, 5);
                if (col == 4 && Boolean.TRUE.equals(scanned)) table.setValueAt(false, row, 5);
                else if (col == 5 && Boolean.TRUE.equals(rejected)) table.setValueAt(false, row, 4);
                saveTableData();
            }
        });

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Logs", logPanel);

        JTextArea extensionArea = new JTextArea(savedExtensions != null ? savedExtensions : ".js, .svg, .css, .png, .jpg, .ttf, .ico, .html, .map, .gif, .woff2, .bcmap, .jpeg, .woff");
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
                    String[] parts = line.split(",", 6);
                    if (parts.length == 6) {
                        String formattedNote = parts[3].replace("|", ", ");
                        tableModel.insertRow(0, new Object[]{
                                parts[0],
                                parts[1],
                                parts[2],
                                formattedNote,
                                Boolean.parseBoolean(parts[4]),
                                Boolean.parseBoolean(parts[5])});
                        loggedRequests.add(parts[1] + "|" + parts[2]);
                        pathToParams.put(parts[1] + "|" + parts[2], new HashSet<>(Arrays.asList(parts[3].split("\\|"))));
                    }
                }
            } catch (IOException e) {
                api.logging().logToError("Failed to load log: " + e.getMessage());
            }
        }
    }


    private File getLogFile() {
        File defaultLogFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api_log.csv");
        return (savedOutputPath != null && !savedOutputPath.isBlank()) ? new File(savedOutputPath) : defaultLogFile;
    }

    private boolean isExcluded(String path) {
        if (savedExtensions == null || savedExtensions.isBlank()) return false;
        return Arrays.stream(savedExtensions.split(",")).map(String::trim).anyMatch(path.toLowerCase()::endsWith);
    }

    private void saveTableData() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(getLogFile(), false))) {
            for (int i = tableModel.getRowCount() - 1; i >= 0; i--) {
                String displayNote = tableModel.getValueAt(i, 3).toString();
                // Remove [new: ...] if exists
                String[] splitNote = displayNote.replaceAll("\\s*\\[new:.*?\\]", "").trim().split(",\\s*");
                String joinedNote = String.join("|", splitNote);

                writer.write(String.join(",",
                        tableModel.getValueAt(i, 0).toString(),
                        tableModel.getValueAt(i, 1).toString(),
                        tableModel.getValueAt(i, 2).toString(),
                        joinedNote,
                        String.valueOf(tableModel.getValueAt(i, 4)),
                        String.valueOf(tableModel.getValueAt(i, 5))));
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
