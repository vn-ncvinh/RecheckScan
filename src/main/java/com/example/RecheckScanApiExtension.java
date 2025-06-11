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

/**
 * Lớp chính của extension, triển khai BurpExtension để tích hợp với Burp Suite.
 */
public class RecheckScanApiExtension implements BurpExtension, ExtensionUnloadingHandler {
    // API chính của Montoya để tương tác với Burp Suite
    private MontoyaApi api;

    // Các biến lưu trữ cài đặt của người dùng
    private String savedExtensions;
    private String savedOutputPath;
    private boolean highlightEnabled = false;
    private boolean noteEnabled = false;
    private boolean autoBypassNoParamGet = false;

    // Model cho các bảng dữ liệu, chứa tất cả thông tin API
    private DefaultTableModel tableModel;

    // Các tập hợp để theo dõi các request và tham số đã thấy, giúp tránh trùng lặp và phát hiện tham số mới
    private final Set<String> loggedRequests = new HashSet<>();
    private final Map<String, Set<String>> pathToParams = new HashMap<>();

    // Các nhãn (Label) để hiển thị thống kê
    private final JLabel totalLbl    = new JLabel("Total: 0");
    private final JLabel scannedLbl  = new JLabel("Scanned: 0");
    private final JLabel rejectedLbl = new JLabel("Rejected: 0");
    private final JLabel bypassLbl   = new JLabel("Bypass: 0");
    private final JLabel unverifiedLbl   = new JLabel("Unverified: 0");

    /**
     * Phương thức khởi tạo, được Burp gọi khi extension được tải.
     * @param api Đối tượng MontoyaApi để tương tác với Burp.
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Recheck Scan API");
        api.extension().registerUnloadingHandler(this); // Đăng ký xử lý khi extension được gỡ bỏ

        loadSavedSettings(); // Tải các cài đặt đã lưu
        SwingUtilities.invokeLater(this::createUI); // Tạo giao diện người dùng trên luồng Event Dispatch Thread (EDT)

        // Đăng ký một HTTP handler để xử lý các request/response đi qua Burp
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                // Không cần xử lý request trước khi gửi đi, cho qua
                return RequestToBeSentAction.continueWith(request);
            }

            /**
             * Xử lý mỗi response HTTP mà Burp nhận được.
             */
            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                HttpRequest request = response.initiatingRequest();
                String method = request.method();

                // 1. Bỏ qua các request không cần thiết
                if (method.equals("OPTIONS")) return ResponseReceivedAction.continueWith(response);
                ToolType sourceType = response.toolSource().toolType();
                if (sourceType == ToolType.EXTENSIONS) return ResponseReceivedAction.continueWith(response);

                boolean isScanner = sourceType == ToolType.SCANNER;
                String host = request.httpService().host();
                String path = request.pathWithoutQuery();
                String uniqueKey = host + "|" + path; // Tạo một khóa định danh duy nhất cho mỗi API endpoint

                // 2. Xử lý đặc biệt cho các request từ Scanner: chỉ cập nhật trạng thái "Scanned"
                if (isScanner) {
                    SwingUtilities.invokeLater(() -> {
                        for (int i = 0; i < tableModel.getRowCount(); i++) {
                            String existingHost = tableModel.getValueAt(i, 1).toString();
                            String existingPath = tableModel.getValueAt(i, 2).toString();
                            if (host.equals(existingHost) && path.equals(existingPath)) {
                                tableModel.setValueAt(true, i, 4); // Cập nhật cột "Scanned" thành true
                                break;
                            }
                        }
                    });
                    return ResponseReceivedAction.continueWith(response);
                }

                // 3. Logic chính: chỉ xử lý các request trong scope và không thuộc danh sách loại trừ
                if (api.scope().isInScope(request.url()) && !isExcluded(path)) {
                    String query = request.query();

                    // 3a. Tự động bypass các API GET không có tham số nếu tùy chọn được bật
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

                    // 3b. Phân tích và thu thập các tham số từ URL
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
                    final boolean[] states = new boolean[2]; // Dùng để lấy trạng thái ra khỏi luồng UI

                    // 3c. Cập nhật hoặc thêm mới dòng vào bảng trên luồng giao diện người dùng (EDT) để đảm bảo an toàn
                    try {
                        SwingUtilities.invokeAndWait(() -> {
                            boolean found = false;
                            for (int i = 0; i < tableModel.getRowCount(); i++) {
                                String existingHost = tableModel.getValueAt(i, 1).toString();
                                String existingPath = tableModel.getValueAt(i, 2).toString();
                                if (host.equals(existingHost) && path.equals(existingPath)) {
                                    tableModel.setValueAt(finalDisplayNote, i, 3);
                                    states[0] = Boolean.TRUE.equals(tableModel.getValueAt(i, 4)); // Scanned
                                    states[1] = Boolean.TRUE.equals(tableModel.getValueAt(i, 6)); // Bypass
                                    found = true;
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

                    // 3d. Cập nhật highlight và note cho request trong Proxy history dựa trên trạng thái đã lấy
                    boolean isScannedState = states[0];
                    boolean isBypassedState = states[1];

                    if (highlightEnabled) {
                        if (isScannedState || isBypassedState) {
                            response.annotations().setHighlightColor(HighlightColor.YELLOW);
                        }
                    }
                    if (noteEnabled) {
                        if (isScannedState) {
                            response.annotations().setNotes("Scanned");
                        } else if (isBypassedState) {
                            response.annotations().setNotes("Bypassed");
                        }
                    }
                }
                return ResponseReceivedAction.continueWith(response);
            }
        });
    }


    /**
     * Phương thức chính để xây dựng toàn bộ giao diện người dùng cho extension.
     */
    private void createUI() {
        // Tạo TableModel tùy chỉnh để quản lý dữ liệu và hành vi của bảng
        tableModel = new DefaultTableModel(new Object[]{"Method", "Host", "Path", "Note", "Scanned", "Rejected", "Bypass"}, 0) {
            
            /**
             * Quy định cột nào có thể được chỉnh sửa.
             * Nếu API đã được Scanned, không cho phép sửa Rejected và Bypass.
             */
            @Override
            public boolean isCellEditable(int row, int column) {
                if (column == 5 || column == 6) { // Cột "Rejected" và "Bypass"
                    boolean isScanned = Boolean.TRUE.equals(getValueAt(row, 4));
                    return !isScanned; // Chỉ cho phép sửa nếu chưa bị Scanned
                }
                return false; // Các cột khác không được sửa
            }

            /**
             * Định nghĩa kiểu dữ liệu cho từng cột để hiển thị đúng (vd: checkbox cho boolean)
             */
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return (columnIndex >= 4 && columnIndex <= 6) ? Boolean.class : String.class;
            }

            /**
             * Ghi đè logic khi một giá trị trong ô được thay đổi.
             * Dùng để đảm bảo chỉ có 1 trong 3 checkbox trạng thái (Scanned, Rejected, Bypass) được chọn.
             */
            @Override
            public void setValueAt(Object aValue, int row, int col) {
                super.setValueAt(aValue, row, col); // Thực hiện thay đổi giá trị trước

                // Nếu không phải là cột trạng thái thì bỏ qua
                if (col < 4 || col > 6) {
                    return;
                }
                // Nếu một ô được tích (true), bỏ tích 2 ô còn lại
                if (Boolean.TRUE.equals(aValue)) {
                    for (int i = 4; i <= 6; i++) {
                        if (i != col) {
                            super.setValueAt(false, row, i);
                        }
                    }
                }
            }
        };

        // Lắng nghe mọi thay đổi trên model (thêm, sửa, xóa) để lưu dữ liệu và cập nhật thống kê
        TableModelListener tableListener = e -> {
            if (e.getType() == TableModelEvent.UPDATE || e.getType() == TableModelEvent.INSERT || e.getType() == TableModelEvent.DELETE) {
                saveTableData();
                updateStats();
            }
        };
        tableModel.addTableModelListener(tableListener);

        // Tạo TabbedPane để chứa các tab
        JTabbedPane tabs = new JTabbedPane();

        // --- Thiết lập tab Unscanned ---
        JTable unscannedTable = createCommonTable();
        final TableRowSorter<DefaultTableModel> unscannedSorter = new TableRowSorter<>(tableModel);
        unscannedTable.setRowSorter(unscannedSorter);

        // Tạo bộ lọc (Filter) chỉ hiển thị các dòng chưa được xử lý
        final RowFilter<Object, Object> unscannedStatusFilter = new RowFilter<>() {
            public boolean include(Entry<?, ?> entry) {
                boolean scanned = Boolean.TRUE.equals(entry.getValue(4));
                boolean rejected = Boolean.TRUE.equals(entry.getValue(5));
                boolean bypass = Boolean.TRUE.equals(entry.getValue(6));
                return !scanned && !rejected && !bypass;
            }
        };
        unscannedSorter.setRowFilter(unscannedStatusFilter); // Áp dụng bộ lọc ban đầu

        // Tạo và xử lý nút Refresh cho tab Unscanned
        JButton unscannedRefreshButton = new JButton("Refresh");
        unscannedRefreshButton.addActionListener(e -> unscannedSorter.setRowFilter(unscannedStatusFilter));

        JPanel unscannedPanel = createApiPanel("Search unscanned paths:", unscannedTable, unscannedRefreshButton, (keyword, sorter) -> {
            RowFilter<Object, Object> textFilter = keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2);
            sorter.setRowFilter(textFilter != null ? RowFilter.andFilter(Arrays.asList(unscannedStatusFilter, textFilter)) : unscannedStatusFilter);
        });
        tabs.addTab("Unscanned", unscannedPanel);

        // --- Thiết lập tab Logs ---
        JTable logsTable = createCommonTable();
        final TableRowSorter<DefaultTableModel> logsSorter = new TableRowSorter<>(tableModel);
        logsTable.setRowSorter(logsSorter);
        
        JButton logsRefreshButton = new JButton("Refresh");
        logsRefreshButton.addActionListener(e -> logsSorter.setRowFilter(logsSorter.getRowFilter()));

        JPanel logsPanel = createApiPanel("Search all paths:", logsTable, logsRefreshButton, (keyword, sorter) -> {
            sorter.setRowFilter(keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2));
        });
        tabs.addTab("Logs", logsPanel);


        // --- Thiết lập tab Settings ---
        JTextArea extensionArea = new JTextArea(savedExtensions != null ? savedExtensions : ".js, .svg, .css, .png, .jpg, .ttf, .ico, .html, .map, .gif, .woff2, .bcmap, .jpeg, .woff");
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                outputPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });

        JCheckBox highlightCheckBox = new JCheckBox("Highlight Scanned/Bypassed requests in Proxy history");
        highlightCheckBox.setSelected(highlightEnabled);
        highlightCheckBox.addActionListener(e -> {
            highlightEnabled = highlightCheckBox.isSelected();
            saveSettings();
        });

        JCheckBox noteCheckBox = new JCheckBox("Add Note to Scanned/Bypassed requests in Proxy history");
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
            savedExtensions = extensionArea.getText().trim();
            savedOutputPath = outputPathField.getText().trim();
            saveSettings();

            // Tạm thời gỡ bỏ listener để tránh lỗi ghi đè file log khi đang tải lại
            tableModel.removeTableModelListener(tableListener);

            tableModel.setRowCount(0);
            loggedRequests.clear();
            loadLogData(); // Tải lại dữ liệu

            // Tự động tích bypass cho các API thoả mãn trong log
            if (autoBypassNoParamGet) {
                SwingUtilities.invokeLater(() -> {
                    for (int i = 0; i < tableModel.getRowCount(); i++) {
                        String method = tableModel.getValueAt(i, 0).toString();
                        Object noteValue = tableModel.getValueAt(i, 3);
                        String note = (noteValue == null) ? "" : noteValue.toString().trim();
                        if ("GET".equals(method) && note.isEmpty()) {
                            boolean isScanned = Boolean.TRUE.equals(tableModel.getValueAt(i, 4));
                            boolean isRejected = Boolean.TRUE.equals(tableModel.getValueAt(i, 5));
                            if (!isScanned && !isRejected) {
                                tableModel.setValueAt(true, i, 6);
                            }
                        }
                    }
                });
            }

            // Thêm lại listener để các thao tác sau đó hoạt động bình thường
            tableModel.addTableModelListener(tableListener);

            JOptionPane.showMessageDialog(null, "Settings saved and project loaded.");
        });

        tabs.addTab("Settings", SettingsPanel.create(extensionArea, outputPathField, browseButton, highlightCheckBox, noteCheckBox, autoBypassCheckBox, applyButton, totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl));

        // Lắp ráp giao diện chính
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);
        loadLogData();
    }

    /**
     * Phương thức hỗ trợ để tạo một JTable với các thuộc tính chung.
     * @return một đối tượng JTable đã được cấu hình.
     */
    private JTable createCommonTable() {
        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFillsViewportHeight(true);

        // Vô hiệu hóa việc kéo thả để sắp xếp lại cột, cố định vị trí các cột
        table.getTableHeader().setReorderingAllowed(false);

        // Tùy chỉnh cách hiển thị cho các ô checkbox
        table.setDefaultRenderer(Boolean.class, (tbl, value, isSelected, hasFocus, row, column) -> {
            JCheckBox checkBox = new JCheckBox();
            checkBox.setSelected(Boolean.TRUE.equals(value));
            checkBox.setHorizontalAlignment(SwingConstants.CENTER);
            checkBox.setOpaque(true);
            checkBox.setBackground(isSelected ? tbl.getSelectionBackground() : tbl.getBackground());
            if (column == 4) checkBox.setEnabled(false); // Làm cho ô "Scanned" trông bị vô hiệu hóa
            return checkBox;
        });

        // Tùy chỉnh cách hiển thị cho các ô chuỗi (để tô đỏ tham số mới)
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

        // Gán sự kiện Ctrl+C để sao chép đường dẫn
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

    /**
     * Phương thức hỗ trợ để tạo một panel hoàn chỉnh chứa bảng, thanh tìm kiếm và nút refresh.
     */
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

        // Xử lý sự kiện tìm kiếm
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
    
    /**
     * Một functional interface để xử lý logic tìm kiếm một cách linh hoạt.
     */
    @FunctionalInterface
    interface SearchHandler {
        void apply(String keyword, TableRowSorter<DefaultTableModel> sorter);
    }

    /**
     * Lưu các cài đặt vào file cấu hình.
     */
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

    /**
     * Tải các cài đặt từ file cấu hình khi khởi động.
     */
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


    /**
     * Tải dữ liệu log vào bảng.
     */
    private void loadLogData() {
        File logFile = getLogFile();
        if (logFile.exists()) {
            try {
                tableModel.setRowCount(0);
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

    /**
     * Lấy đường dẫn file log, ưu tiên đường dẫn do người dùng cài đặt.
     */
    private File getLogFile() {
        File defaultLogFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api_log.csv");
        return (savedOutputPath != null && !savedOutputPath.isBlank()) ? new File(savedOutputPath) : defaultLogFile;
    }

    /**
     * Kiểm tra xem một đường dẫn có bị loại trừ dựa trên phần mở rộng hay không.
     */
    private boolean isExcluded(String path) {
        if (savedExtensions == null || savedExtensions.isBlank()) return false;
        return Arrays.stream(savedExtensions.split(",")).map(String::trim).anyMatch(path.toLowerCase()::endsWith);
    }

    /**
     * Lưu toàn bộ dữ liệu từ bảng vào file log.
     */
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


    /**
     * Tính toán và cập nhật các nhãn thống kê.
     */
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

    /**
     * Được gọi khi extension bị gỡ bỏ, đảm bảo dữ liệu trong bảng được lưu lại.
     */
    @Override
    public void extensionUnloaded() {
        saveTableData();
    }
}