package com.example;


import burp.api.montoya.*;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.*;
import javax.swing.RowFilter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class RecheckScanApiExtension implements BurpExtension, ExtensionUnloadingHandler {
    private MontoyaApi api;
    private String savedExtensions;
    private String savedOutputPath;
    private DefaultTableModel tableModel;
    private final Set<String> loggedRequests = new HashSet<>();
    private final Map<String, Set<String>> pathToParams = new HashMap<>();
    private boolean highlightEnabled = false;
    private boolean noteEnabled = false;
    private boolean autoBypassNoParamGet = false;

    private final JLabel totalLbl    = new JLabel("Total: 0");
    private final JLabel scannedLbl  = new JLabel("Scanned: 0");
    private final JLabel rejectedLbl = new JLabel("Rejected: 0");
    private final JLabel bypassLbl   = new JLabel("Bypass: 0");
    private final JLabel unverifiedLbl   = new JLabel("Unverified: 0");

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
                                tableModel.setValueAt(true, i, 4);
                                break;
                            }
                        }
                    });
                    return ResponseReceivedAction.continueWith(response);
                }

                if (api.scope().isInScope(request.url()) && !isExcluded(path)) {
                    String query = request.query();

                    if (autoBypassNoParamGet && "GET".equals(method) && (query == null || query.isBlank())) {
                        SwingUtilities.invokeLater(() -> {
                            boolean found = false;
                            for (int i = 0; i < tableModel.getRowCount(); i++) {
                                if (uniqueKey.equals(tableModel.getValueAt(i, 1) + "|" + tableModel.getValueAt(i, 2))) {
                                    if (!Boolean.TRUE.equals(tableModel.getValueAt(i, 4)) && !Boolean.TRUE.equals(tableModel.getValueAt(i, 5))) {
                                        tableModel.setValueAt(true, i, 6);
                                    }
                                    found = true;
                                    break;
                                }
                            }
                            if (!found) {
                                tableModel.insertRow(0, new Object[]{method, host, path, "", false, false, true});
                                loggedRequests.add(uniqueKey);
                            }
                        });
                        return ResponseReceivedAction.continueWith(response);
                    }


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

                    String displayNote = knownParams.stream().sorted().collect(Collectors.joining(", "));

                    if (!addedParams.isEmpty()) {
                        displayNote += " [new: " + addedParams.stream().sorted().collect(Collectors.joining(", ")) + "]";
                    }

                    final String finalDisplayNote = displayNote;
                    final boolean[] hehe = new boolean[1];

                    try {
                        SwingUtilities.invokeAndWait(() -> {
                            boolean found = false;
                            for (int i = 0; i < tableModel.getRowCount(); i++) {
                                String existingHost = tableModel.getValueAt(i, 1).toString();
                                String existingPath = tableModel.getValueAt(i, 2).toString();
                                if (host.equals(existingHost) && path.equals(existingPath)) {
                                    boolean scanned = Boolean.TRUE.equals(tableModel.getValueAt(i, 4));
                                    tableModel.setValueAt(finalDisplayNote, i, 3);
                                    found = true;
                                    hehe[0] = scanned;
                                    break;
                                }
                            }
                            if (!found) {
                                Object[] newRow = new Object[]{method, host, path, finalDisplayNote, false, false, false};
                                tableModel.insertRow(0, newRow);
                                loggedRequests.add(uniqueKey);
                            }
                        });
                    } catch (InterruptedException | InvocationTargetException e) {
                        throw new RuntimeException(e);
                    }

                    if (hehe[0]) {
                        if (highlightEnabled) response.annotations().setHighlightColor(HighlightColor.YELLOW);
                        if (noteEnabled) response.annotations().setNotes("Scanned");
                    }
                }
                return ResponseReceivedAction.continueWith(response);
            }
        });
    }


    private void createUI() {
        tableModel = new DefaultTableModel(new Object[]{"Method", "Host", "Path", "Note", "Scanned", "Rejected", "Bypass"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 5 || column == 6;
            }
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return (columnIndex >= 4 && columnIndex <= 6) ? Boolean.class : String.class;
            }
        };

        TableModelListener tableListener = e -> {
            if (e.getType() == TableModelEvent.UPDATE || e.getType() == TableModelEvent.INSERT || e.getType() == TableModelEvent.DELETE) {
                saveTableData();
                updateStats();
            }
        };
        tableModel.addTableModelListener(tableListener);

        JTabbedPane tabs = new JTabbedPane();

        // --- Unscanned Panel ---
        JTable unscannedTable = createCommonTable();
        final TableRowSorter<DefaultTableModel> unscannedSorter = new TableRowSorter<>(tableModel);
        unscannedTable.setRowSorter(unscannedSorter);

        final RowFilter<Object, Object> unscannedStatusFilter = new RowFilter<>() {
            public boolean include(Entry<?, ?> entry) {
                boolean scanned = Boolean.TRUE.equals(entry.getValue(4));
                boolean rejected = Boolean.TRUE.equals(entry.getValue(5));
                boolean bypass = Boolean.TRUE.equals(entry.getValue(6));
                return !scanned && !rejected && !bypass;
            }
        };
        unscannedSorter.setRowFilter(unscannedStatusFilter);

        JButton unscannedRefreshButton = new JButton("Refresh");
        unscannedRefreshButton.addActionListener(e -> unscannedSorter.setRowFilter(unscannedStatusFilter));

        JPanel unscannedPanel = createApiPanel("Search unscanned paths:", unscannedTable, unscannedRefreshButton, (keyword, sorter) -> {
            RowFilter<Object, Object> textFilter = keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2);
            sorter.setRowFilter(textFilter != null ? RowFilter.andFilter(Arrays.asList(unscannedStatusFilter, textFilter)) : unscannedStatusFilter);
        });
        tabs.addTab("Unscanned", unscannedPanel);

        // --- Logs Panel ---
        JTable logsTable = createCommonTable();
        final TableRowSorter<DefaultTableModel> logsSorter = new TableRowSorter<>(tableModel);
        logsTable.setRowSorter(logsSorter);
        
        JButton logsRefreshButton = new JButton("Refresh");
        logsRefreshButton.addActionListener(e -> logsSorter.setRowFilter(logsSorter.getRowFilter()));

        JPanel logsPanel = createApiPanel("Search all paths:", logsTable, logsRefreshButton, (keyword, sorter) -> {
            sorter.setRowFilter(keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2));
        });
        tabs.addTab("Logs", logsPanel);


        // --- Settings Panel ---
        JTextArea extensionArea = new JTextArea(savedExtensions != null ? savedExtensions : ".js, .svg, .css, .png, .jpg, .ttf, .ico, .html, .map, .gif, .woff2, .bcmap, .jpeg, .woff");
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                outputPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });

        JCheckBox highlightCheckBox = new JCheckBox("Highlight scanned requests in Proxy history");
        highlightCheckBox.setSelected(highlightEnabled);
        highlightCheckBox.addActionListener(e -> {
            highlightEnabled = highlightCheckBox.isSelected();
            saveSettings();
        });

        JCheckBox noteCheckBox = new JCheckBox("Add note to scanned requests in Proxy history");
        noteCheckBox.setSelected(noteEnabled);
        noteCheckBox.addActionListener(e -> {
            noteEnabled = noteCheckBox.isSelected();
            saveSettings();
        });

        JCheckBox autoBypassCheckBox = new JCheckBox("Auto-bypass GET APIs without params");
        autoBypassCheckBox.setSelected(autoBypassNoParamGet);
        autoBypassCheckBox.addActionListener(e -> {
            autoBypassNoParamGet = autoBypassCheckBox.isSelected();
            saveSettings();
        });

        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            // Save current settings from the text fields
            savedExtensions = extensionArea.getText().trim();
            savedOutputPath = outputPathField.getText().trim();
            saveSettings();

            // FIXED: Temporarily remove the listener to prevent saving an empty table
            tableModel.removeTableModelListener(tableListener);

            // Safely clear and reload the table
            tableModel.setRowCount(0);
            loggedRequests.clear();
            loadLogData(); // Reloads from the (potentially new) log file path

            // Re-add the listener for future operations
            tableModel.addTableModelListener(tableListener);

            JOptionPane.showMessageDialog(null, "Settings saved and project loaded.");
        });

        tabs.addTab("Settings", SettingsPanel.create(extensionArea, outputPathField, browseButton, highlightCheckBox, noteCheckBox, autoBypassCheckBox, applyButton, totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl));

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);
        loadLogData();
    }

    private JTable createCommonTable() {
        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFillsViewportHeight(true);

        table.setDefaultRenderer(Boolean.class, (tbl, value, isSelected, hasFocus, row, column) -> {
            JCheckBox checkBox = new JCheckBox();
            checkBox.setSelected(Boolean.TRUE.equals(value));
            checkBox.setHorizontalAlignment(SwingConstants.CENTER);
            checkBox.setOpaque(true);
            checkBox.setBackground(isSelected ? tbl.getSelectionBackground() : tbl.getBackground());
            if (column == 4) checkBox.setEnabled(false);
            return checkBox;
        });

        table.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == 3 && value != null && value.toString().contains("[new:")) {
                    c.setForeground(Color.RED);
                } else {
                    c.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
                }
                return c;
            }
        });

        table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke("ctrl C"), "copyPath");
        table.getActionMap().put("copyPath", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                if (selectedRows.length > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int viewRow : selectedRows) {
                        int modelRow = table.convertRowIndexToModel(viewRow);
                        Object value = tableModel.getValueAt(modelRow, 2);
                        if (value != null) sb.append(value.toString()).append("\n");
                    }
                    StringSelection selection = new StringSelection(sb.toString().trim());
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                }
            }
        });
        return table;
    }

    private JPanel createApiPanel(String searchLabel, JTable table, JButton refreshButton, SearchHandler handler) {
        JPanel panel = new JPanel(new BorderLayout(0, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel topPanel = new JPanel(new BorderLayout(5, 0));
        
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        searchPanel.add(new JLabel(searchLabel));
        JTextField searchField = new JTextField();
        searchField.setPreferredSize(new Dimension(400, 28));
        searchPanel.add(searchField);

        topPanel.add(searchPanel, BorderLayout.CENTER);
        if(refreshButton != null) {
            topPanel.add(refreshButton, BorderLayout.EAST);
        }
        
        panel.add(topPanel, BorderLayout.NORTH);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { filter(); }
            public void removeUpdate(DocumentEvent e) { filter(); }
            public void changedUpdate(DocumentEvent e) { filter(); }
            private void filter() {
                handler.apply(searchField.getText().trim(), (TableRowSorter<DefaultTableModel>) table.getRowSorter());
            }
        });
        
        return panel;
    }
    
    @FunctionalInterface
    interface SearchHandler {
        void apply(String keyword, TableRowSorter<DefaultTableModel> sorter);
    }

    private void saveSettings() {
        try {
            File configFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api.txt");
            if (!configFile.getParentFile().exists()) configFile.getParentFile().mkdirs();
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(configFile))) {
                writer.write(savedExtensions + "\n" + highlightEnabled + "\n" + noteEnabled + "\n" + savedOutputPath + "\n" + autoBypassNoParamGet);
            }
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null, "Failed to save settings: " + ex.getMessage());
        }
    }

    private void loadSavedSettings() {
        try {
            File configFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api.txt");
            if (configFile.exists()) {
                List<String> lines = Files.readAllLines(configFile.toPath());
                if (!lines.isEmpty()) savedExtensions = lines.get(0).trim();
                if (lines.size() >= 2) highlightEnabled = Boolean.parseBoolean(lines.get(1).trim());
                if (lines.size() >= 3) noteEnabled = Boolean.parseBoolean(lines.get(2).trim());
                if (lines.size() >= 4) savedOutputPath = lines.get(3).trim();
                if (lines.size() >= 5) autoBypassNoParamGet = Boolean.parseBoolean(lines.get(4).trim());
            }
        } catch (IOException e) {
            api.logging().logToError("Failed to load settings: " + e.getMessage());
        }
    }


    private void loadLogData() {
        File logFile = getLogFile();
        if (logFile.exists()) {
            try {
                // This method is now safe to be called when the listener is detached
                List<String> lines = Files.readAllLines(logFile.toPath());
                List<Object[]> newRows = new ArrayList<>();
                for (String line : lines) {
                    String[] parts = line.split(",", 7);
                    if (parts.length == 7) {
                        String formattedNote = parts[3].replace("|", ", ");
                        newRows.add(0, new Object[]{
                                parts[0], parts[1], parts[2], formattedNote,
                                Boolean.parseBoolean(parts[4]), Boolean.parseBoolean(parts[5]), Boolean.parseBoolean(parts[6])
                        });
                        loggedRequests.add(parts[1] + "|" + parts[2]);
                        pathToParams.put(parts[1] + "|" + parts[2], new HashSet<>(Arrays.asList(parts[3].split("\\|"))));
                    }
                }
                for(Object[] row : newRows) {
                    tableModel.addRow(row);
                }
            } catch (IOException e) {
                api.logging().logToError("Failed to load log: " + e.getMessage());
            }
        }
        updateStats();
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
            for (int i = 0; i < tableModel.getRowCount(); i++) {
                String displayNote = tableModel.getValueAt(i, 3).toString();
                String[] splitNote = displayNote.replaceAll("\\s*\\[new:.*?\\]", "").trim().split(",\\s*");
                String joinedNote = String.join("|", splitNote);
                writer.write(String.join(",",
                        tableModel.getValueAt(i, 0).toString(),
                        tableModel.getValueAt(i, 1).toString(),
                        tableModel.getValueAt(i, 2).toString(),
                        joinedNote,
                        String.valueOf(tableModel.getValueAt(i, 4)),
                        String.valueOf(tableModel.getValueAt(i, 5)),
                        String.valueOf(tableModel.getValueAt(i, 6))));
                writer.newLine();
            }
        } catch (IOException e) {
            api.logging().logToError("Failed to save log: " + e.getMessage());
        }
    }


    private void updateStats(){
        int total = tableModel.getRowCount();
        int scanned=0, rejected=0, bypass=0;
        for(int i=0;i<total;i++){
            if(Boolean.TRUE.equals(tableModel.getValueAt(i,4))) scanned++;
            if(Boolean.TRUE.equals(tableModel.getValueAt(i,5))) rejected++;
            if(Boolean.TRUE.equals(tableModel.getValueAt(i,6))) bypass++;
        }
        totalLbl.setText("Total: "+total);
        scannedLbl.setText("Scanned: "+scanned);
        rejectedLbl.setText("Rejected: "+rejected);
        bypassLbl.setText("Bypass: "+bypass);
        int unverified = total - scanned - rejected - bypass;
        unverifiedLbl.setText("Unverified: "+ unverified);
    }

    @Override
    public void extensionUnloaded() {
        saveTableData();
    }
}