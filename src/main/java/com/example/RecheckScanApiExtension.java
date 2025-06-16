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
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;
import java.util.stream.Collectors;

public class RecheckScanApiExtension implements BurpExtension, ExtensionUnloadingHandler {
    private MontoyaApi api;
    private DatabaseManager databaseManager;

    private String savedExtensions;
    private String savedOutputPath;
    private boolean highlightEnabled = false;
    private boolean noteEnabled = false;
    private boolean autoBypassNoParamGet = false;

    private DefaultTableModel tableModel;
    private final Map<Integer, Integer> modelRowToDbId = new HashMap<>();

    private final JLabel totalLbl = new JLabel("Total: 0");
    private final JLabel scannedLbl = new JLabel("Scanned: 0");
    private final JLabel rejectedLbl = new JLabel("Rejected: 0");
    private final JLabel bypassLbl = new JLabel("Bypass: 0");
    private final JLabel unverifiedLbl = new JLabel("Unverified: 0");

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Recheck Scan API (SQLite)");
        api.extension().registerUnloadingHandler(this);

        loadSavedSettings();

        databaseManager = new DatabaseManager(api);
        databaseManager.initialize(savedOutputPath);

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
                ToolType sourceType = response.toolSource().toolType();

                if (method.equals("OPTIONS") || sourceType == ToolType.INTRUDER || sourceType == ToolType.EXTENSIONS) {
                    return ResponseReceivedAction.continueWith(response);
                }

                String host = request.httpService().host();
                String path = request.pathWithoutQuery();

                // Trường hợp A: Request từ Scanner.
                if (sourceType == ToolType.SCANNER) {
                    new Thread(() -> {
                        Integer dbId = databaseManager.findIdByHostPath(host, path);
                        if (dbId != null) {
                            databaseManager.updateApiStatus(dbId, "is_scanned", true);
                            databaseManager.updateApiStatus(dbId, "is_rejected", false);
                            databaseManager.updateApiStatus(dbId, "is_bypassed", false);
                            SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                        }
                    }).start();

                    if (highlightEnabled) response.annotations().setHighlightColor(HighlightColor.YELLOW);
                    if (noteEnabled) response.annotations().setNotes("Scanned");
                    return ResponseReceivedAction.continueWith(response);
                }

                // Trường hợp B: Request trong scope.
                if (api.scope().isInScope(request.url()) && !isExcludedByExtension(path)) {
                    String query = request.query();
                    boolean isGetWithoutParams = "GET".equals(method) && (query == null || query.isBlank());

                    // Nhánh B1: Tự động bypass.
                    if (autoBypassNoParamGet && isGetWithoutParams) {
                        new Thread(() -> {
                            Object[] resultRow = databaseManager.insertOrBypassApi(method, host, path);
                            if (resultRow != null) {
                                SwingUtilities.invokeLater(() -> updateOrInsertTableRow(resultRow));
                            }
                        }).start();

                        if (highlightEnabled) response.annotations().setHighlightColor(HighlightColor.YELLOW);
                        if (noteEnabled) response.annotations().setNotes("Bypassed");
                        return ResponseReceivedAction.continueWith(response);
                    }

                    // Nhánh B2: Xử lý request thông thường (có thể có param mới).
                    Set<String> newParamsSet = new HashSet<>();
                    if (query != null && !query.isBlank()) {
                        for (String pair : query.split("&")) {
                             String[] kv = pair.split("=", 2);
                             if (kv.length > 0) newParamsSet.add(kv[0].trim());
                        }
                    }

                    // Đồng bộ lấy trạng thái cũ để quyết định việc highlight/note
                    Object[] oldState = databaseManager.getApiState(host, path);
                    boolean shouldAnnotateAsScanned = false;
                    boolean isBypassed = false;

                    if (oldState != null) {
                        boolean dbIsScanned = (boolean) oldState[0];
                        String oldParamsStr = (String) oldState[1];
                        String newParamsAsStr = newParamsSet.stream().sorted().collect(Collectors.joining("|"));

                        // Nếu params không đổi, giữ nguyên trạng thái scanned.
                        // Nếu params thay đổi, coi như chưa scan (cho mục đích annotation).
                        if (newParamsAsStr.equals(oldParamsStr)) {
                            shouldAnnotateAsScanned = dbIsScanned;
                        } else {
                            shouldAnnotateAsScanned = false;
                        }
                        
                        // Lấy trạng thái bypassed từ DB để highlight
                        Object[] fullStatus = databaseManager.getApiStatus(host, path);
                        if (fullStatus != null) {
                             isBypassed = (boolean) fullStatus[2];
                        }
                    }

                    // Áp dụng annotation DỰA TRÊN LOGIC ĐÃ XỬ LÝ
                    if (highlightEnabled && (shouldAnnotateAsScanned || isBypassed)) {
                        response.annotations().setHighlightColor(HighlightColor.YELLOW);
                    }
                    if (noteEnabled) {
                        if (shouldAnnotateAsScanned) {
                             response.annotations().setNotes("Scanned");
                        } else if (isBypassed) {
                             response.annotations().setNotes("Bypassed");
                        }
                    }

                    // Bất đồng bộ cập nhật CSDL và UI
                    new Thread(() -> {
                        Object[] resultRow = databaseManager.insertOrUpdateApi(method, host, path, newParamsSet);
                        if (resultRow != null) {
                            SwingUtilities.invokeLater(() -> updateOrInsertTableRow(resultRow));
                        }
                    }).start();
                    
                    return ResponseReceivedAction.continueWith(response);
                }

                // Trường hợp C: Fallback cho các request khác (ví dụ: out of scope nhưng đã có trong DB)
                Object[] status = databaseManager.getApiStatus(host, path);
                if (status != null) {
                    boolean isScanned = (boolean) status[0];
                    boolean isBypassed = (boolean) status[2];

                    if (highlightEnabled && (isScanned || isBypassed)) {
                        response.annotations().setHighlightColor(HighlightColor.YELLOW);
                    }
                    if (noteEnabled) {
                        if (isScanned) {
                            response.annotations().setNotes("Scanned");
                        } else if (isBypassed) {
                            response.annotations().setNotes("Bypassed");
                        }
                    }
                }

                return ResponseReceivedAction.continueWith(response);
            }
        });
    }

    private void updateOrInsertTableRow(Object[] rowData) {
        int dbId = (int) rowData[7];
        Integer modelRowIndex = findModelRowByDbId(dbId);

        if (modelRowIndex != null) {
            tableModel.setValueAt(rowData[3], modelRowIndex, 3);
            tableModel.setValueAt(rowData[4], modelRowIndex, 4);
            tableModel.setValueAt(rowData[5], modelRowIndex, 5);
            tableModel.setValueAt(rowData[6], modelRowIndex, 6);
        } else {
            tableModel.insertRow(0, rowData);
            remapAllIndices();
        }
        updateStats();
    }

    private Integer findModelRowByDbId(int dbId) {
        return modelRowToDbId.entrySet().stream()
                .filter(entry -> entry.getValue().equals(dbId))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
    }

    private void remapAllIndices() {
        modelRowToDbId.clear();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            Integer id = (Integer) tableModel.getValueAt(i, 7);
            if (id != null) {
                modelRowToDbId.put(i, id);
            }
        }
    }

    private void createUI() {
        tableModel = new DefaultTableModel(new Object[]{"Method", "Host", "Path", "Note", "Scanned", "Rejected", "Bypass", "id"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                 if (column == 5 || column == 6) {
                    boolean isScanned = Boolean.TRUE.equals(getValueAt(row, 4));
                    return !isScanned;
                }
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex >= 4 && columnIndex <= 6) return Boolean.class;
                if (columnIndex == 7) return Integer.class;
                return String.class;
            }

            @Override
            public void setValueAt(Object aValue, int row, int col) {
                if (!(Thread.currentThread().getStackTrace()[2].getMethodName().equals("updateOrInsertTableRow"))) {
                    super.setValueAt(aValue, row, col);
                } else {
                     super.setValueAt(aValue, row, col);
                     return;
                }
                if (col >= 4 && col <= 6) {
                    Integer id = (Integer) getValueAt(row, 7);
                    if (id != null) {
                        if (Boolean.TRUE.equals(aValue)) {
                            for (int i = 4; i <= 6; i++) {
                                final boolean isChecked = (i == col);
                                if (!isChecked) {
                                    super.setValueAt(false, row, i);
                                }
                                final int finalI = i;
                                new Thread(() -> {
                                    String dbColumn = switch (finalI) {
                                        case 4 -> "is_scanned";
                                        case 5 -> "is_rejected";
                                        case 6 -> "is_bypassed";
                                        default -> null;
                                    };
                                    if (dbColumn != null) {
                                        databaseManager.updateApiStatus(id, dbColumn, isChecked);
                                    }
                                }).start();
                            }
                        } else {
                            String dbColumn = switch (col) {
                                case 4 -> "is_scanned";
                                case 5 -> "is_rejected";
                                case 6 -> "is_bypassed";
                                default -> null;
                            };
                             if (dbColumn != null) {
                                 new Thread(() -> databaseManager.updateApiStatus(id, dbColumn, false)).start();
                             }
                        }
                    }
                }
                updateStats();
            }
        };

        JTabbedPane tabs = new JTabbedPane();
        JTable unscannedTable = createCommonTable();
        hideIdColumn(unscannedTable);
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

        JTable logsTable = createCommonTable();
        hideIdColumn(logsTable);
        final TableRowSorter<DefaultTableModel> logsSorter = new TableRowSorter<>(tableModel);
        logsTable.setRowSorter(logsSorter);
        JButton logsRefreshButton = new JButton("Refresh");
        logsRefreshButton.addActionListener(e -> logsSorter.setRowFilter(logsSorter.getRowFilter()));
        JPanel logsPanel = createApiPanel("Search all paths:", logsTable, logsRefreshButton, (keyword, sorter) -> {
            sorter.setRowFilter(keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2));
        });
        tabs.addTab("Logs", logsPanel);

        JTextArea extensionArea = new JTextArea(savedExtensions != null ? savedExtensions : ".js,.svg,.css,.png,.jpg,.ttf,.ico,.html,.map,.gif,.woff2,.bcmap,.jpeg,.woff");
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                outputPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        JCheckBox highlightCheckBox = new JCheckBox("Highlight Scanned/Bypassed requests in Proxy history", highlightEnabled);
        highlightCheckBox.addActionListener(e -> {
            highlightEnabled = highlightCheckBox.isSelected();
            saveSettings();
        });
        JCheckBox noteCheckBox = new JCheckBox("Add Note to Scanned/Bypassed requests in Proxy history", noteEnabled);
        noteCheckBox.addActionListener(e -> {
            noteEnabled = noteCheckBox.isSelected();
            saveSettings();
        });
        JCheckBox autoBypassCheckBox = new JCheckBox("Auto-bypass GET APIs without params", autoBypassNoParamGet);
        autoBypassCheckBox.addActionListener(e -> {
            autoBypassNoParamGet = autoBypassCheckBox.isSelected();
            saveSettings();
        });
        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            savedExtensions = extensionArea.getText().trim();
            savedOutputPath = outputPathField.getText().trim();
            saveSettings();
            databaseManager.close();
            databaseManager.initialize(savedOutputPath);
            loadDataFromDb();
            JOptionPane.showMessageDialog(null, "Settings saved and project loaded from database.");
        });
        tabs.addTab("Settings", SettingsPanel.create(extensionArea, outputPathField, browseButton, highlightCheckBox, noteCheckBox, autoBypassCheckBox, applyButton, totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl));
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);
        loadDataFromDb();
    }

    private void hideIdColumn(JTable table) {
        TableColumn idColumn = table.getColumnModel().getColumn(7);
        idColumn.setMinWidth(0);
        idColumn.setMaxWidth(0);
        idColumn.setWidth(0);
    }

    private void loadDataFromDb() {
        tableModel.setRowCount(0);
        modelRowToDbId.clear();
        List<Object[]> rows = databaseManager.loadApiData();
        for (int i = 0; i < rows.size(); i++) {
            Object[] rowData = rows.get(i);
            tableModel.addRow(rowData);
            modelRowToDbId.put(i, (Integer) rowData[7]);
        }
        updateStats();
    }

    private boolean isExcludedByExtension(String path) {
        if (savedExtensions == null || savedExtensions.isBlank()) return false;
        return Arrays.stream(savedExtensions.split(","))
                     .map(String::trim)
                     .anyMatch(ext -> !ext.isEmpty() && path.toLowerCase().endsWith(ext));
    }
    
    private JTable createCommonTable() {
        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(false);
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
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        JPanel topPanel = new JPanel(new BorderLayout(5, 0));
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        searchPanel.add(new JLabel(searchLabel));
        JTextField searchField = new JTextField();
        searchField.setPreferredSize(new Dimension(400, 28));
        searchPanel.add(searchField);
        topPanel.add(searchPanel, BorderLayout.CENTER);
        if (refreshButton != null) {
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
    
    private void updateStats() {
        int total = tableModel.getRowCount();
        int scanned = 0, rejected = 0, bypass = 0;
        for (int i = 0; i < total; i++) {
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 4))) scanned++;
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 5))) rejected++;
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 6))) bypass++;
        }
        totalLbl.setText("Total: " + total);
        scannedLbl.setText("Scanned: " + scanned);
        rejectedLbl.setText("Rejected: " + rejected);
        bypassLbl.setText("Bypass: " + bypass);
        int unverified = total - scanned - rejected - bypass;
        unverifiedLbl.setText("Unverified: " + unverified);
    }

    @Override
    public void extensionUnloaded() {
        databaseManager.close();
    }
}