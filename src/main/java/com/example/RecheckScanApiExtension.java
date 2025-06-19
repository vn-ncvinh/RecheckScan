package com.example;

import burp.api.montoya.*;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.params.*;
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
import java.util.*;
import java.util.List;

/**
 * Lớp chính của extension "Recheck Scan API".
 * <p>
 * Lớp này thực hiện các nhiệm vụ chính:
 * 1. Khởi tạo giao diện người dùng (một tab mới trong Burp Suite).
 * 2. Đăng ký một {@link HttpHandler} để lắng nghe và xử lý tất cả các request/response.
 * 3. Tương tác với {@link DatabaseManager} để lưu trữ và truy xuất dữ liệu API.
 * 4. Quản lý trạng thái và cài đặt của người dùng.
 */
public class RecheckScanApiExtension implements BurpExtension, ExtensionUnloadingHandler {
    /**
     * Đối tượng API chính của Montoya, cung cấp quyền truy cập vào các chức năng cốt lõi của Burp.
     */
    private MontoyaApi api;
    /**
     * Đối tượng quản lý cơ sở dữ liệu, đóng gói tất cả các thao tác với SQLite.
     */
    private DatabaseManager databaseManager;

    // Các biến lưu trữ cài đặt của người dùng, được tải từ tệp cấu hình.
    private String savedExtensions;
    private String savedOutputPath;
    private String savedStatusCodes;
    private boolean highlightEnabled = false;
    private boolean noteEnabled = false;
    private boolean autoBypassNoParamGet = false;

    /**
     * Model cho JTable, chứa dữ liệu API được hiển thị trên giao diện.
     */
    private DefaultTableModel tableModel;
    /**
     * Một Map quan trọng để ánh xạ chỉ số dòng hiển thị trên JTable (có thể thay đổi do sắp xếp)
     * sang ID duy nhất trong cơ sở dữ liệu (không đổi).
     * Điều này đảm bảo việc cập nhật trạng thái luôn đúng dòng.
     */
    private final Map<Integer, Integer> modelRowToDbId = new HashMap<>();

    // Các nhãn (JLabel) để hiển thị thống kê trên tab Settings.
    private final JLabel totalLbl = new JLabel("Total: 0");
    private final JLabel scannedLbl = new JLabel("Scanned: 0");
    private final JLabel rejectedLbl = new JLabel("Rejected: 0");
    private final JLabel bypassLbl = new JLabel("Bypass: 0");
    private final JLabel unverifiedLbl = new JLabel("Unverified: 0");

    /**
     * Phương thức chính được Burp gọi khi extension được tải.
     *
     * @param api Đối tượng MontoyaApi do Burp cung cấp.
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Recheck Scan API (v2)");
        // Đăng ký handler để dọn dẹp tài nguyên (đóng kết nối CSDL) khi extension bị gỡ.
        api.extension().registerUnloadingHandler(this);

        // Tải các cài đặt đã lưu từ tệp.
        loadSavedSettings();
        // Khởi tạo trình quản lý CSDL.
        databaseManager = new DatabaseManager(api);
        databaseManager.initialize(savedOutputPath);

        // Tạo giao diện người dùng trên luồng Event Dispatch Thread (EDT) của Swing để đảm bảo an toàn luồng.
        SwingUtilities.invokeLater(this::createUI);

        // Đăng ký HttpHandler để xử lý các request/response đi qua Burp.
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                // Không cần xử lý request trước khi gửi đi, cho qua.
                return RequestToBeSentAction.continueWith(request);
            }

            /**
             * Xử lý mỗi response HTTP mà Burp nhận được. Đây là nơi logic cốt lõi được thực thi.
             */
            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                // Lọc bỏ các API trả về status code bị loại trừ.
                if (isExcludedStatusCode(response.statusCode())) {
                    return ResponseReceivedAction.continueWith(response);
                }

                HttpRequest request = response.initiatingRequest();
                String method = request.method();
                ToolType sourceType = response.toolSource().toolType();

                // Lọc bỏ các request không cần thiết (OPTIONS, Intruder, các extension khác).
                if (method.equals("OPTIONS") || sourceType == ToolType.INTRUDER || sourceType == ToolType.EXTENSIONS) {
                    return ResponseReceivedAction.continueWith(response);
                }

                String host = request.httpService().host();
                String path = request.pathWithoutQuery();
                
                // Trích xuất tất cả tham số từ cả URL và body.
                Set<String> requestParams = extractParameters(request);
                
                // Trường hợp 1: Request từ Scanner -> xử lý các tham số đã được quét.
                if (sourceType == ToolType.SCANNER) {
                    new Thread(() -> {
                        boolean updated = databaseManager.processScannedParameters(method, host, path, requestParams);
                        // Nếu CSDL có thay đổi, tải lại dữ liệu trên giao diện.
                        if (updated) {
                            SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                        }
                    }).start();
                } 
                // Trường hợp 2: Request từ các công cụ khác (Proxy, Repeater) và nằm trong scope.
                else if (api.scope().isInScope(request.url()) && !isExcludedByExtension(path)) {
                    // Nhánh 2a: Tự động bypass cho GET không có tham số.
                    boolean isGetWithoutParams = "GET".equals(method) && requestParams.isEmpty();
                    if (autoBypassNoParamGet && isGetWithoutParams) {
                        new Thread(() -> {
                            boolean updated = databaseManager.autoBypassApi(method, host, path);
                            if (updated) {
                                SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                            }
                        }).start();
                         // Thêm highlight/note ngay lập tức cho request này.
                         if (highlightEnabled) response.annotations().setHighlightColor(HighlightColor.YELLOW);
                         if (noteEnabled) response.annotations().setNotes("Bypassed");
                    } else {
                        // Nhánh 2b: Xử lý request thông thường để tìm và ghi nhận tham số mới.
                        new Thread(() -> {
                            databaseManager.insertOrUpdateApi(method, host, path, requestParams);
                            // Tải lại UI để phản ánh thay đổi (nếu có param mới được thêm).
                            SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                        }).start();
                    }
                }

                // Luôn kiểm tra trạng thái cuối cùng trong CSDL để áp dụng highlight và note.
                Object[] status = databaseManager.getApiStatus(method, host, path);
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

    /**
     * Trích xuất tham số từ cả URL (query string) và body của request.
     * <p>
     * Phương thức này hợp nhất tham số từ hai nguồn vào một Set duy nhất.
     * Nó sử dụng các parser tích hợp của Montoya API để xử lý các định dạng phổ biến.
     *
     * @param request HttpRequest cần phân tích.
     * @return một Set chứa tên của tất cả các tham số.
     */
    private Set<String> extractParameters(HttpRequest request) {

        Set<String> allParamNames = new HashSet<>();

        // 1. Lấy tham số từ URL (query string)
        List<ParsedHttpParameter> urlParams = request.parameters(HttpParameterType.URL);
        if (urlParams != null && !urlParams.isEmpty()) {
            urlParams.stream()
                    .map(ParsedHttpParameter::name)
                    .forEach(allParamNames::add);
        }

        // 2. Lấy tham số từ Body nếu có
        if (request.body().length() > 0) {
            ContentType contentType = request.contentType();
            
            List<ParsedHttpParameter> bodyParams = null;

            switch (contentType) {
                case JSON:
                    bodyParams = request.parameters(HttpParameterType.JSON);
                    break;
                case URL_ENCODED:
                    bodyParams = request.parameters(HttpParameterType.BODY);
                    break;
                case MULTIPART:
                     bodyParams = request.parameters(HttpParameterType.BODY);
                     break;
                case XML:
                     bodyParams = request.parameters(HttpParameterType.XML);
                     break;
                default:
                    break;
            }

            if (bodyParams != null && !bodyParams.isEmpty()) {
                bodyParams.stream()
                        .map(ParsedHttpParameter::name)
                        .forEach(allParamNames::add);
            }
        }

        return allParamNames;
    }


    /**
     * Cập nhật một dòng đã có hoặc chèn một dòng mới vào JTable.
     * @param rowData Dữ liệu trả về từ DatabaseManager, bao gồm cả ID.
     */
    private void updateOrInsertTableRow(Object[] rowData) {
        int dbId = (int) rowData[7];
        Integer modelRowIndex = findModelRowByDbId(dbId);

        if (modelRowIndex != null) { // API này đã tồn tại trên bảng -> cập nhật.
            tableModel.setValueAt(rowData[3], modelRowIndex, 3); // Cập nhật cột Unscanned Params.
            tableModel.setValueAt(rowData[4], modelRowIndex, 4); // Cập nhật cột Scanned.
            tableModel.setValueAt(rowData[5], modelRowIndex, 5); // Cập nhật cột Rejected
            tableModel.setValueAt(rowData[6], modelRowIndex, 6); // Cập nhật cột Bypass
        } else { // API mới -> chèn vào đầu bảng.
            tableModel.insertRow(0, rowData);
            // Sau khi chèn, phải cập nhật lại toàn bộ map ánh xạ.
            remapAllIndices();
        }
        updateStats();
    }

    /**
     * Tìm chỉ số dòng trong TableModel (dữ liệu hiển thị) dựa trên ID trong CSDL.
     * @param dbId ID duy nhất của dòng trong CSDL.
     * @return Chỉ số dòng trên JTable, hoặc null nếu không tìm thấy.
     */
    private Integer findModelRowByDbId(int dbId) {
        return modelRowToDbId.entrySet().stream()
                .filter(entry -> entry.getValue().equals(dbId))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
    }

    /**
     * Ánh xạ lại toàn bộ chỉ số dòng trên JTable với ID trong CSDL.
     * Cần được gọi mỗi khi có sự thay đổi về cấu trúc bảng (thêm/xóa dòng).
     */
    private void remapAllIndices() {
        modelRowToDbId.clear();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            Integer id = (Integer) tableModel.getValueAt(i, 7);
            if (id != null) {
                modelRowToDbId.put(i, id);
            }
        }
    }

    /**
     * Khởi tạo toàn bộ giao diện người dùng của extension.
     */
    private void createUI() {
        // Khởi tạo TableModel với các cột và định nghĩa kiểu dữ liệu.
        tableModel = new DefaultTableModel(new Object[]{"Method", "Host", "Path", "Unscanned Params", "Scanned", "Rejected", "Bypass", "id"}, 0) {
            /**
             * Xác định các ô có thể chỉnh sửa. Chỉ cho phép tick vào "Rejected" và "Bypass".
             * Cột "Scanned" được quản lý tự động.
             */
            @Override
            public boolean isCellEditable(int row, int column) {
                 if (column == 5 || column == 6) { // Cột "Rejected" và "Bypass"
                    boolean isScanned = Boolean.TRUE.equals(getValueAt(row, 4));
                    return !isScanned;
                }
                return false;
            }

            /**
             * Định nghĩa kiểu dữ liệu cho các cột để JTable có thể render đúng (e.g., checkbox cho boolean).
             */
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex >= 4 && columnIndex <= 6) return Boolean.class;
                if (columnIndex == 7) return Integer.class;
                return String.class;
            }

            /**
             * Ghi đè phương thức này để xử lý sự kiện người dùng tick vào các checkbox.
             * Khi một checkbox được tick, trạng thái tương ứng sẽ được cập nhật vào CSDL.
             */
            @Override
            public void setValueAt(Object aValue, int row, int col) {
                // Tạm thời bỏ qua việc cập nhật UI từ chính logic bên trong (tránh lặp vô hạn).
                if (!(Thread.currentThread().getStackTrace()[2].getMethodName().equals("updateOrInsertTableRow"))) {
                    super.setValueAt(aValue, row, col); // Cập nhật giá trị trên UI trước.
                } else {
                     super.setValueAt(aValue, row, col);
                     return;
                }

                // Chỉ xử lý các cột checkbox trạng thái.
                if (col >= 4 && col <= 6) {
                    Integer id = (Integer) getValueAt(row, 7); // Lấy ID của dòng từ cột ẩn.
                    if (id != null) {
                        // Logic đảm bảo chỉ 1 trong 3 checkbox (Scanned, Rejected, Bypassed) được chọn tại một thời điểm.
                        if (Boolean.TRUE.equals(aValue)) {
                            for (int i = 4; i <= 6; i++) {
                                final boolean isChecked = (i == col);
                                if (!isChecked) {
                                    super.setValueAt(false, row, i); // Bỏ tick các ô khác trên UI.
                                }
                                // Cập nhật CSDL trong một luồng riêng.
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
                             // Nếu người dùng bỏ tick một ô, cập nhật trạng thái đó trong CSDL.
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
                updateStats(); // Cập nhật các nhãn thống kê.
            }
        };

        // Bố cục chính của tab extension.
        JTabbedPane tabs = new JTabbedPane();

        // --- Cài đặt Tab "Unscanned" ---
        JTable unscannedTable = createCommonTable();
        hideIdColumn(unscannedTable); // Ẩn cột ID.
        final TableRowSorter<DefaultTableModel> unscannedSorter = new TableRowSorter<>(tableModel);
        unscannedTable.setRowSorter(unscannedSorter);

        // Tạo bộ lọc để chỉ hiển thị các dòng chưa có trạng thái nào (unscanned, unrejected, unbypassed).
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

        // --- Cài đặt Tab "Logs" ---
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

        // --- Cài đặt Tab "Settings" ---
        JTextArea extensionArea = new JTextArea(savedExtensions != null ? savedExtensions : ".js,.svg,.css,.png,.jpg,.ttf,.ico,.html,.map,.gif,.woff2,.bcmap,.jpeg,.woff");
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JTextField excludeStatusCodesField = new JTextField(savedStatusCodes != null ? savedStatusCodes : "404,405");
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
            savedStatusCodes = excludeStatusCodesField.getText().trim();
            saveSettings();
            // Khởi tạo lại CSDL nếu đường dẫn thay đổi.
            databaseManager.close();
            databaseManager.initialize(savedOutputPath);
            loadDataFromDb();
            JOptionPane.showMessageDialog(null, "Settings saved and project loaded from database.");
        });
        tabs.addTab("Settings", SettingsPanel.create(extensionArea, outputPathField, browseButton, highlightCheckBox, noteCheckBox, autoBypassCheckBox, applyButton, totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl, excludeStatusCodesField));
        
        // Đăng ký tab chính vào giao diện Burp.
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);
        
        // Tải dữ liệu lần đầu.
        loadDataFromDb();
    }

    /**
     * Helper method để ẩn cột ID khỏi giao diện người dùng.
     */
    private void hideIdColumn(JTable table) {
        TableColumn idColumn = table.getColumnModel().getColumn(7);
        idColumn.setMinWidth(0);
        idColumn.setMaxWidth(0);
        idColumn.setWidth(0);
    }

    /**
     * Xóa dữ liệu cũ trên bảng và tải lại toàn bộ từ CSDL.
     * Đồng thời cập nhật lại map `modelRowToDbId`.
     */
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

    /**
     * Kiểm tra xem một đường dẫn có bị loại trừ dựa trên phần mở rộng hay không.
     * @param path Đường dẫn của request.
     * @return true nếu bị loại trừ.
     */
    private boolean isExcludedByExtension(String path) {
        if (savedExtensions == null || savedExtensions.isBlank()) return false;
        return Arrays.stream(savedExtensions.replace(" ", "").split(","))
                     .map(String::trim)
                     .anyMatch(ext -> !ext.isEmpty() && path.toLowerCase().endsWith(ext));
    }
    
    /**
     * Phương thức tiện ích để tạo một JTable với các thuộc tính chung.
     */
    private JTable createCommonTable() {
        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(false);
        // Tùy chỉnh cách hiển thị cho cột boolean (dùng checkbox).
        table.setDefaultRenderer(Boolean.class, (tbl, value, isSelected, hasFocus, row, column) -> {
            JCheckBox checkBox = new JCheckBox();
            checkBox.setSelected(Boolean.TRUE.equals(value));
            checkBox.setHorizontalAlignment(SwingConstants.CENTER);
            checkBox.setOpaque(true);
            checkBox.setBackground(isSelected ? tbl.getSelectionBackground() : tbl.getBackground());
            if (column == 4) checkBox.setEnabled(false); // Vô hiệu hóa checkbox cột "Scanned".
            return checkBox;
        });
        // Tùy chỉnh cách hiển thị cho cột Note (bôi đỏ nếu có param mới).
        table.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == 3 && value != null) {
                    c.setForeground(Color.RED);
                } else {
                    c.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
                }
                return c;
            }
        });
        // Bắt sự kiện Ctrl+C để sao chép đường dẫn.
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
     * Phương thức tiện ích để tạo một panel hoàn chỉnh chứa bảng, thanh tìm kiếm và nút refresh.
     */
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
    
    /**
     * Lưu các cài đặt hiện tại vào tệp cấu hình.
     */
    private void saveSettings() {
        try {
            File configFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api.txt");
            if (!configFile.getParentFile().exists()) configFile.getParentFile().mkdirs();
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(configFile))) {
                writer.write(savedExtensions + "\n" + highlightEnabled + "\n" + noteEnabled + "\n" + savedOutputPath + "\n" + autoBypassNoParamGet+ "\n" + savedStatusCodes);
            }
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null, "Failed to save settings: " + ex.getMessage());
        }
    }

    /**
     * Tải các cài đặt từ tệp cấu hình khi khởi động.
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
                if (lines.size() >= 6) savedStatusCodes = lines.get(5).trim();
            }
        } catch (IOException e) {
            api.logging().logToError("Failed to load settings: " + e.getMessage());
        }
    }
    /**
     * Kiểm tra xem một mã trạng thái HTTP nhất định có nên bị loại trừ dựa trên cài đặt của người dùng hay không.
     * @param statusCode Mã trạng thái HTTP cần kiểm tra.
     * @return true nếu mã trạng thái nằm trong danh sách bị loại trừ, ngược lại là false.
     */
    private boolean isExcludedStatusCode(int statusCode) {
        if (savedStatusCodes == null || savedStatusCodes.isBlank()) {
            return false;
        }

        Set<Integer> excludedCodes = new HashSet<>();
        try {
            for (String s : savedStatusCodes.split(",")) {
                try {
                    excludedCodes.add(Integer.parseInt(s.trim()));
                } catch (NumberFormatException e) {
                }
            }
        } catch (Exception e) {
            return false;
        }

        return excludedCodes.contains(statusCode);
    }
    
    /**
     * Tính toán và cập nhật các nhãn thống kê.
     */
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

    /**
     * Được gọi khi extension bị gỡ bỏ.
     * Đóng kết nối cơ sở dữ liệu để giải phóng tài nguyên.
     */
    @Override
    public void extensionUnloaded() {
        databaseManager.close();
    }
}