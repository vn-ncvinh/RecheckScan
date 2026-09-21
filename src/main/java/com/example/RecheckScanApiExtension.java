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
import java.io.StringReader;
import java.io.StringWriter;
import java.util.*;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;

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

    /**
     * Toàn bộ thao tác CSDL đi qua đúng một luồng nền.
     * <p>
     * Vừa giới hạn tài nguyên (thay cho việc tạo một Thread mới cho mỗi response),
     * vừa tuần tự hoá truy cập vào {@link java.sql.Connection} của SQLite vốn không thread-safe,
     * đồng thời bảo toàn thứ tự các thao tác ghi cho cùng một API.
     */
    private final ExecutorService dbExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "RecheckScan-DB");
        thread.setDaemon(true);
        return thread;
    });

    // Các biến lưu trữ cài đặt của người dùng, được tải từ persistence extension data.
    // Tất cả đều `volatile`: ghi trên EDT (khi người dùng bấm Apply) nhưng đọc trên
    // các luồng HTTP của Burp, nên cần đảm bảo thay đổi được nhìn thấy ngay.
    private volatile String exclude_extensions;
    private volatile String savedOutputPath;
    private volatile String exclude_status_code;
    private volatile String path_parameter_rules;
    private volatile String ignore_path_parameter_rules;
    private volatile boolean highlightEnabled = false;
    private volatile boolean noteEnabled = false;
    private volatile boolean autoBypassNoParam = false;
    private volatile PathParameterRules pathRules = PathParameterRules.empty();
    /**
     * Danh sách status code bị loại trừ, được biên dịch sẵn để không phải parse lại cho từng response.
     */
    private volatile Set<Integer> excludedStatusCodes = Set.of();

    /**
     * Model cho JTable, chứa dữ liệu API được hiển thị trên giao diện.
     */
    private DefaultTableModel tableModel;
    /**
     * Ánh xạ ID trong CSDL sang chỉ số dòng trong TableModel, cho phép cập nhật
     * đúng một dòng trong O(1) thay vì tải lại toàn bộ bảng sau mỗi thay đổi.
     * Chỉ được truy cập trên EDT.
     */
    private final Map<Integer, Integer> dbIdToModelRow = new HashMap<>();
    /**
     * Trạng thái mới nhất của từng API, khoá theo {@link #statusKey}.
     * <p>
     * Handler HTTP cần biết trạng thái ngay lập tức để đặt highlight/note trước khi trả response,
     * nên không thể chờ luồng CSDL. Cache này cho phép tra cứu đồng bộ trong O(1)
     * thay vì chạy một truy vấn SQL trên luồng HTTP của Burp.
     */
    private final Map<String, Object[]> statusCache = new ConcurrentHashMap<>();
    /**
     * Cờ chặn ghi ngược xuống CSDL khi bảng đang được đồng bộ từ chính CSDL.
     * Chỉ được truy cập trên EDT.
     */
    private boolean suppressDbWrite = false;
    /**
     * Gom nhiều lần cập nhật thống kê liên tiếp thành một lần tính lại.
     */
    private javax.swing.Timer statsRefreshTimer;

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
                String rawPath = request.pathWithoutQuery();
                String path = normalizePath(rawPath);
                
                // Trích xuất tất cả tham số từ cả URL và body.
                Set<String> requestParams = extractParameters(request);
                
                // Trường hợp 1: Request từ Scanner -> xử lý các tham số đã được quét.
                if (sourceType == ToolType.SCANNER) {
                    submitDbTask(() -> databaseManager.processScannedParameters(method, host, path, requestParams));
                }
                // Trường hợp 2: Request từ các công cụ khác (Proxy, Repeater) và nằm trong scope.
                else if (api.scope().isInScope(request.url()) && !isExcludedByExtension(rawPath)) {
                    // Nếu request từ Repeater, đánh dấu vào DB.
                    if (sourceType == ToolType.REPEATER) {
                        submitDbTask(() -> databaseManager.updateRepeaterStatus(method, host, path));
                    }

                    // Nhánh 2a: Tự động bypass cho API không có tham số, áp dụng cho mọi HTTP method
                    // và chỉ khi người dùng đã bật tuỳ chọn tương ứng trong Settings.
                    if (requestParams.isEmpty() && autoBypassNoParam) {
                        submitDbTask(() -> databaseManager.autoBypassApi(method, host, path));
                         // Thêm highlight/note ngay lập tức cho request này.
                         if (highlightEnabled) response.annotations().setHighlightColor(HighlightColor.YELLOW);
                         if (noteEnabled) response.annotations().setNotes("Bypassed");
                    } else {
                        // Nhánh 2b: Ghi nhận API và tìm tham số mới. API không có tham số vẫn được
                        // ghi vào CSDL ở đây khi tuỳ chọn auto-bypass đang tắt.
                        submitDbTask(() -> databaseManager.insertOrUpdateApi(method, host, path, requestParams));
                    }
                    // Áp dụng highlight và note dựa trên trạng thái đã biết của API.
                    // Đọc từ cache trong bộ nhớ: annotation phải được đặt trước khi trả response
                    // nên không thể chờ luồng CSDL, và cũng không nên chạy SQL trên luồng HTTP.
                    Object[] status = statusCache.get(statusKey(method, host, path));
                    if (status != null) {
                        boolean isScanned = Boolean.TRUE.equals(status[4]);
                        boolean isRejected = Boolean.TRUE.equals(status[5]);
                        boolean isBypassed = Boolean.TRUE.equals(status[6]);

                        if (highlightEnabled && (isScanned || isBypassed)) {
                            response.annotations().setHighlightColor(HighlightColor.YELLOW);
                        }
                        if (noteEnabled) {
                            if (isScanned) {
                                response.annotations().setNotes("Scanned");
                            } else if (isBypassed) {
                                response.annotations().setNotes("Bypassed");
                            } else if (isRejected) {
                                response.annotations().setNotes("Rejected");
                            }
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
     * Đẩy một thao tác CSDL sang luồng nền, rồi đồng bộ kết quả lên cache và giao diện.
     * <p>
     * Chỉ dòng thực sự thay đổi mới được cập nhật, thay cho việc tải lại toàn bộ bảng.
     *
     * @param task Thao tác trả về dòng dữ liệu đã thay đổi, hoặc null nếu CSDL không đổi.
     */
    private void submitDbTask(Supplier<Object[]> task) {
        runOnDbThread(() -> {
            Object[] rowData = task.get();
            if (rowData == null) {
                return;
            }
            // Cập nhật cache ngay trên luồng CSDL để response kế tiếp thấy trạng thái mới nhất.
            cacheStatus(rowData);
            SwingUtilities.invokeLater(() -> updateOrInsertTableRow(rowData));
        });
    }

    /**
     * Đẩy một tác vụ sang luồng CSDL, bỏ qua một cách im lặng nếu extension đang được gỡ bỏ.
     * <p>
     * Burp có thể còn vài response đang dang dở sau khi executor đã shutdown; khi đó
     * không được để RejectedExecutionException thoát ra luồng HTTP của Burp.
     */
    private void runOnDbThread(Runnable task) {
        try {
            dbExecutor.execute(task);
        } catch (RejectedExecutionException e) {
            // Extension đang unload, không còn gì để ghi nữa.
        }
    }

    /**
     * Khoá định danh một API trong {@link #statusCache}.
     * Dùng ký tự NUL làm dấu phân cách để không thể trùng với nội dung method/host/path.
     */
    private static String statusKey(String method, String host, String path) {
        return method + '\0' + host + '\0' + path;
    }

    /**
     * Ghi trạng thái của một dòng vào cache phục vụ highlight/note.
     */
    private void cacheStatus(Object[] rowData) {
        statusCache.put(statusKey((String) rowData[0], (String) rowData[1], (String) rowData[2]), rowData);
    }

    /**
     * Dựng lại toàn bộ cache trạng thái từ dữ liệu vừa đọc khỏi CSDL.
     * Được gọi trên luồng CSDL, nơi không có thao tác ghi nào khác chen ngang.
     */
    private void rebuildStatusCache(List<Object[]> rows) {
        statusCache.clear();
        for (Object[] rowData : rows) {
            cacheStatus(rowData);
        }
    }

    /**
     * Cập nhật một dòng đã có hoặc chèn một dòng mới vào JTable. Chỉ được gọi trên EDT.
     *
     * @param rowData Dữ liệu trả về từ DatabaseManager, bao gồm cả ID.
     */
    private void updateOrInsertTableRow(Object[] rowData) {
        Integer dbId = (Integer) rowData[8]; // Index của ID
        Integer modelRowIndex = dbIdToModelRow.get(dbId);

        // Những thay đổi dưới đây đến từ CSDL, không được ghi ngược trở lại CSDL.
        suppressDbWrite = true;
        try {
            if (modelRowIndex != null) { // API này đã tồn tại trên bảng -> cập nhật.
                // Cột 3..7: Unscanned Params, Scanned, Rejected, Bypass, Repeater.
                for (int column = 3; column <= 7; column++) {
                    tableModel.setValueAt(rowData[column], modelRowIndex, column);
                }
            } else { // API mới -> chèn vào đầu bảng.
                tableModel.insertRow(0, rowData);
                // insertRow(0) đẩy mọi dòng cũ xuống một bậc, nên chỉ cần dịch map
                // thay vì quét lại toàn bộ bảng.
                dbIdToModelRow.replaceAll((id, modelRow) -> modelRow + 1);
                dbIdToModelRow.put(dbId, 0);
            }
        } finally {
            suppressDbWrite = false;
        }
        scheduleStatsUpdate();
    }

    /**
     * Khởi tạo toàn bộ giao diện người dùng của extension.
     */
    private void createUI() {
        // Khởi tạo TableModel với các cột
        // Thứ tự rất quan trọng: Method, Host, Path, Unscanned, Scanned, Rejected, Bypass, Repeater(ẩn), id(ẩn)
        tableModel = new DefaultTableModel(new Object[]{"Method", "Host", "Path", "Unscanned Params", "Scanned", "Rejected", "Bypass", "Repeater", "id"}, 0) {
            /**
             * Sửa đổi logic cho phép chỉnh sửa ô.
             * - "Rejected": Chỉ có thể sửa nếu API chưa "Scanned" VÀ đã được gửi từ "Repeater".
             * - "Bypass": Có thể sửa nếu API chưa "Scanned".
             * - Các cột khác không thể sửa trực tiếp trên bảng.
             */
            @Override
            public boolean isCellEditable(int row, int column) {
                boolean isScanned = Boolean.TRUE.equals(getValueAt(row, 4));
                // Nếu đã được quét, không cho phép chỉnh sửa bất kỳ trạng thái nào.
                if (isScanned) {
                    return false;
                }

                // Logic cho cột "Rejected" (index 5)
                if (column == 5) {
                    // Lấy trạng thái từ cột "Repeater" (index 7)
                    boolean isFromRepeater = Boolean.TRUE.equals(getValueAt(row, 7));
                    return isFromRepeater; // Chỉ cho phép sửa nếu `isFromRepeater` là true.
                }

                // Logic cho cột "Bypass" (index 6)
                if (column == 6) {
                    return true;
                }

                return false;
            }

            /**
             * Định nghĩa kiểu dữ liệu cho các cột để JTable có thể render đúng.
             */
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex >= 4 && columnIndex <= 7) return Boolean.class; // Các cột trạng thái (Scanned, Rejected, Bypass, Repeater)
                if (columnIndex == 8) return Integer.class; // Cột ID
                return String.class;
            }

            /**
             * Ghi đè phương thức này để xử lý sự kiện người dùng tick vào các checkbox.
             * Khi một checkbox được tick, trạng thái tương ứng sẽ được cập nhật vào CSDL.
             */
            @Override
            public void setValueAt(Object aValue, int row, int col) {
                super.setValueAt(aValue, row, col); // Cập nhật giá trị trên UI trước.

                // Bỏ qua khi thay đổi đến từ việc đồng bộ CSDL lên bảng, để không ghi
                // ngược xuống CSDL đúng những gì vừa đọc ra.
                if (suppressDbWrite) {
                    return;
                }

                // Chỉ xử lý các cột checkbox trạng thái "Rejected" (5) và "Bypass" (6).
                if (col == 5 || col == 6) {
                    Integer id = (Integer) getValueAt(row, 8); // Lấy ID của dòng từ cột ẩn.
                    if (id != null) {
                        boolean isChecked = Boolean.TRUE.equals(aValue);
                        int otherCol = (col == 5) ? 6 : 5;
                        String dbColumn = (col == 5) ? "is_rejected" : "is_bypassed";
                        String otherDbColumn = (col == 5) ? "is_bypassed" : "is_rejected";

                        // Hai trạng thái loại trừ nhau: tick ô này thì bỏ tick ô kia.
                        if (isChecked && Boolean.TRUE.equals(getValueAt(row, otherCol))) {
                            super.setValueAt(false, row, otherCol);
                            runOnDbThread(() -> databaseManager.updateApiStatus(id, otherDbColumn, false));
                        }
                        runOnDbThread(() -> databaseManager.updateApiStatus(id, dbColumn, isChecked));

                        // Giữ cache trạng thái khớp với bảng để highlight/note dùng đúng giá trị.
                        Object[] rowData = new Object[getColumnCount()];
                        for (int column = 0; column < rowData.length; column++) {
                            rowData[column] = getValueAt(row, column);
                        }
                        cacheStatus(rowData);
                    }
                }
                scheduleStatsUpdate(); // Cập nhật các nhãn thống kê.
            }
        };

        // Bố cục chính của tab extension.
        JTabbedPane tabs = new JTabbedPane();

        // --- Cài đặt Tab "Unscanned" ---
        JTable unscannedTable = createCommonTable();
        setupHiddenColumns(unscannedTable); // Ẩn các cột cần thiết (Repeater, id)
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
        unscannedRefreshButton.addActionListener(e -> reloadDataAsync());
        JPanel unscannedPanel = createApiPanel("Search unscanned paths:", unscannedTable, unscannedRefreshButton, (keyword, sorter) -> {
            RowFilter<Object, Object> textFilter = keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2);
            sorter.setRowFilter(textFilter != null ? RowFilter.andFilter(Arrays.asList(unscannedStatusFilter, textFilter)) : unscannedStatusFilter);
        });
        tabs.addTab("Unscanned", unscannedPanel);

        // --- Cài đặt Tab "Logs" ---
        JTable logsTable = createCommonTable();
        setupHiddenColumns(logsTable); // Ẩn các cột cần thiết (Repeater, id)
        final TableRowSorter<DefaultTableModel> logsSorter = new TableRowSorter<>(tableModel);
        logsTable.setRowSorter(logsSorter);
        JButton logsRefreshButton = new JButton("Refresh");
        logsRefreshButton.addActionListener(e -> reloadDataAsync());
        JPanel logsPanel = createApiPanel("Search all paths:", logsTable, logsRefreshButton, (keyword, sorter) -> {
            sorter.setRowFilter(keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2));
        });
        tabs.addTab("Logs", logsPanel);

        // --- Cài đặt Tab "Settings" ---
        JTextArea extensionArea = new JTextArea(exclude_extensions != null ? exclude_extensions : ".js,.svg,.css,.png,.jpg,.ttf,.ico,.html,.map,.gif,.woff2,.bcmap,.jpeg,.woff");
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JTextField excludeStatusCodesField = new JTextField(exclude_status_code != null ? exclude_status_code : "404,405");
        JTextArea pathParameterRulesArea = new JTextArea(path_parameter_rules != null ? path_parameter_rules : "");
        JTextArea ignorePathParameterRulesArea = new JTextArea(ignore_path_parameter_rules != null ? ignore_path_parameter_rules : "");
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
        JCheckBox autoBypassCheckBox = new JCheckBox("Auto-bypass APIs without params", autoBypassNoParam);
        autoBypassCheckBox.addActionListener(e -> {
            autoBypassNoParam = autoBypassCheckBox.isSelected();
            saveSettings();
        });
        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            exclude_extensions = extensionArea.getText().trim();
            savedOutputPath = outputPathField.getText().trim();
            exclude_status_code = excludeStatusCodesField.getText().trim();
            path_parameter_rules = pathParameterRulesArea.getText().trim();
            ignore_path_parameter_rules = ignorePathParameterRulesArea.getText().trim();
            excludedStatusCodes = parseStatusCodes(exclude_status_code);
            pathRules = compilePathRules();
            autoBypassNoParam = autoBypassCheckBox.isSelected();
            saveSettings();

            // Toàn bộ thao tác CSDL chạy trên dbExecutor: vừa không treo giao diện,
            // vừa không đụng độ với các tác vụ đang xử lý traffic.
            applyButton.setEnabled(false);
            final String dbPath = savedOutputPath;
            final boolean normalizePaths = !pathRules.isEmpty();
            final boolean bypassOldRecords = autoBypassNoParam;
            runOnDbThread(() -> {
                // Mở lại CSDL trước để đảm bảo đang làm việc với đúng file.
                databaseManager.reopen(dbPath);

                // *** Áp dụng chuẩn hoá path và bypass cho dữ liệu cũ ***
                if (normalizePaths) {
                    databaseManager.normalizeStoredPaths(this::normalizePath);
                }
                if (bypassOldRecords) {
                    databaseManager.applyAutoBypassToOldRecords();
                }

                List<Object[]> rows = databaseManager.loadApiData();
                rebuildStatusCache(rows);
                // Chỉ báo cho người dùng sau khi mọi thay đổi đã thực sự hoàn tất.
                SwingUtilities.invokeLater(() -> {
                    populateTable(rows);
                    applyButton.setEnabled(true);
                    JOptionPane.showMessageDialog(null, "Settings applied and project reloaded from database.");
                });
            });
        });
        tabs.addTab("Settings", SettingsPanel.create(extensionArea, outputPathField, browseButton, highlightCheckBox, noteCheckBox, autoBypassCheckBox, applyButton, totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl, excludeStatusCodesField, pathParameterRulesArea, ignorePathParameterRulesArea));
        
        // Đăng ký tab chính vào giao diện Burp.
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);

        // Tải dữ liệu lần đầu.
        reloadDataAsync();
    }

    /**
     * Helper method để ẩn các cột không cần thiết khỏi giao diện người dùng.
     * @param table Bảng cần thao tác.
     */
    private void setupHiddenColumns(JTable table) {
        // Ẩn cột "Repeater" (index 7)
        TableColumn repeaterColumn = table.getColumnModel().getColumn(7);
        repeaterColumn.setMinWidth(0);
        repeaterColumn.setMaxWidth(0);
        repeaterColumn.setWidth(0);

        // Ẩn cột "id" (index 8)
        TableColumn idColumn = table.getColumnModel().getColumn(8);
        idColumn.setMinWidth(0);
        idColumn.setMaxWidth(0);
        idColumn.setWidth(0);
    }

    /**
     * Đọc toàn bộ dữ liệu từ CSDL trên luồng nền rồi đổ lên bảng.
     * Chỉ dùng cho các mốc cần nạp lại toàn bộ: khởi động, bấm Refresh, hoặc sau khi Apply.
     */
    private void reloadDataAsync() {
        runOnDbThread(() -> {
            List<Object[]> rows = databaseManager.loadApiData();
            rebuildStatusCache(rows);
            SwingUtilities.invokeLater(() -> populateTable(rows));
        });
    }

    /**
     * Xóa dữ liệu cũ trên bảng và đổ vào dữ liệu vừa đọc từ CSDL.
     * Đồng thời dựng lại map `dbIdToModelRow`. Chỉ được gọi trên EDT.
     */
    private void populateTable(List<Object[]> rows) {
        tableModel.setRowCount(0);
        dbIdToModelRow.clear();
        for (int i = 0; i < rows.size(); i++) {
            Object[] rowData = rows.get(i);
            tableModel.addRow(rowData);
            dbIdToModelRow.put((Integer) rowData[8], i); // Index của ID
        }
        updateStats();
    }

    /**
     * Kiểm tra xem một đường dẫn có bị loại trừ dựa trên phần mở rộng hay không.
     * @param path Đường dẫn của request.
     * @return true nếu bị loại trừ.
     */
    private boolean isExcludedByExtension(String path) {
        if (exclude_extensions == null || exclude_extensions.isBlank()) return false;
        return Arrays.stream(exclude_extensions.replace(" ", "").split(","))
                     .map(String::trim)
                     .anyMatch(ext -> !ext.isEmpty() && path.toLowerCase().endsWith(ext));
    }

    /**
     * Chuẩn hóa các segment động trong URL path theo rule người dùng cấu hình.
     * Ví dụ: /api/report/1684050854912458752/list -> /api/report/{id}/list.
     */
    private String normalizePath(String path) {
        return pathRules.normalize(path);
    }

    /**
     * Biên dịch cấu hình rule path parameter hiện tại, đẩy lỗi cú pháp ra log của Burp.
     */
    private PathParameterRules compilePathRules() {
        return PathParameterRules.compile(path_parameter_rules, ignore_path_parameter_rules, api.logging()::logToError);
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
                if (column == 3 && value != null && !((String)value).isEmpty()) {
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

        // Tạo context menu cho right-click
        JPopupMenu contextMenu = new JPopupMenu();
        
        // MenuItem "Copy API List"
        JMenuItem copyApiListItem = new JMenuItem("Copy API List");
        copyApiListItem.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (selectedRows.length > 0) {
                StringBuilder sb = new StringBuilder();
                for (int viewRow : selectedRows) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    String method = (String) tableModel.getValueAt(modelRow, 0);
                    String path = (String) tableModel.getValueAt(modelRow, 2);
                    Integer id = (Integer) tableModel.getValueAt(modelRow, 8);
                    
                    if (method != null && path != null && id != null) {
                        // Lấy tất cả params từ DB bằng id
                        Set<String> allParams = databaseManager.getAllParamsById(id);
                        
                        sb.append(method).append(" ").append(path);
                        if (!allParams.isEmpty()) {
                            // Sắp xếp params theo alphabet và hiển thị
                            String sortedParams = allParams.stream()
                                    .sorted()
                                    .collect(Collectors.joining(", "));
                            sb.append(" - param: ").append(sortedParams);
                        }
                        sb.append("\n");
                    }
                }
                StringSelection selection = new StringSelection(sb.toString().trim());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
            }
        });
        contextMenu.add(copyApiListItem);

        // Đăng ký mouse listener cho right-click
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                showContextMenu(e);
            }
            
            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                showContextMenu(e);
            }
            
            private void showContextMenu(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    contextMenu.show(table, e.getX(), e.getY());
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
     * Lưu các cài đặt hiện tại vào persistence extension data (đi theo project).
     */
    private void saveSettings() {
        try {
            Properties props = new Properties();
            String settingsStr = api.persistence().extensionData().getString("settings");
            if (settingsStr != null && !settingsStr.isEmpty()) {
                props.load(new StringReader(settingsStr));
            }
            props.setProperty("exclude_extensions", valueOrEmpty(exclude_extensions));
            props.setProperty("highlightEnabled", String.valueOf(highlightEnabled));
            props.setProperty("noteEnabled", String.valueOf(noteEnabled));
            props.remove("outputPath");
            props.setProperty(currentOutputPathKey(), valueOrEmpty(savedOutputPath));
            props.setProperty("autoBypassNoParam", String.valueOf(autoBypassNoParam));
            props.setProperty("exclude_status_code", valueOrEmpty(exclude_status_code));
            props.setProperty("path_parameter_rules", valueOrEmpty(path_parameter_rules));
            props.setProperty("ignore_path_parameter_rules", valueOrEmpty(ignore_path_parameter_rules));
            
            StringWriter writer = new StringWriter();
            props.store(writer, null);
            api.persistence().extensionData().setString("settings", writer.toString());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "Failed to save settings: " + ex.getMessage());
        }
    }

    private String valueOrEmpty(String value) {
        return value == null ? "" : value;
    }

    private String currentOutputPathKey() {
        String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (osName.contains("win")) {
            return "outputPath.windows";
        }
        if (osName.contains("linux")) {
            return "outputPath.linux";
        }
        if (osName.contains("mac")) {
            return "outputPath.mac";
        }
        return "outputPath.other";
    }

    /**
     * Tải các cài đặt từ persistence extension data khi khởi động.
     */
    private void loadSavedSettings() {
        try {
            String settingsStr = api.persistence().extensionData().getString("settings");
            if (settingsStr != null && !settingsStr.isEmpty()) {
                Properties props = new Properties();
                props.load(new StringReader(settingsStr));
                exclude_extensions = props.getProperty("exclude_extensions", "");
                highlightEnabled = Boolean.parseBoolean(props.getProperty("highlightEnabled", "false"));
                noteEnabled = Boolean.parseBoolean(props.getProperty("noteEnabled", "false"));
                savedOutputPath = props.getProperty(currentOutputPathKey(), "");
                autoBypassNoParam = Boolean.parseBoolean(props.getProperty("autoBypassNoParam", "false"));
                exclude_status_code = props.getProperty("exclude_status_code", "");
                path_parameter_rules = props.getProperty("path_parameter_rules", "");
                ignore_path_parameter_rules = props.getProperty("ignore_path_parameter_rules", "");
            }
            if (path_parameter_rules == null) {
                path_parameter_rules = "";
            }
            if (ignore_path_parameter_rules == null) {
                ignore_path_parameter_rules = "";
            }
            pathRules = compilePathRules();
            excludedStatusCodes = parseStatusCodes(exclude_status_code);
        } catch (Exception e) {
            api.logging().logToError("Failed to load settings: " + e.getMessage());
        }
    }
    /**
     * Kiểm tra xem một mã trạng thái HTTP nhất định có nên bị loại trừ dựa trên cài đặt của người dùng hay không.
     * @param statusCode Mã trạng thái HTTP cần kiểm tra.
     * @return true nếu mã trạng thái nằm trong danh sách bị loại trừ, ngược lại là false.
     */
    private boolean isExcludedStatusCode(int statusCode) {
        return excludedStatusCodes.contains(statusCode);
    }

    /**
     * Phân tích chuỗi status code người dùng nhập thành một tập hợp sẵn sàng tra cứu.
     * Được biên dịch trước tại thời điểm Apply thay vì parse lại cho từng response.
     *
     * @param rawStatusCodes Chuỗi các mã, phân tách bởi dấu phẩy.
     * @return Tập hợp bất biến các mã hợp lệ; rỗng nếu không có cấu hình.
     */
    private Set<Integer> parseStatusCodes(String rawStatusCodes) {
        if (rawStatusCodes == null || rawStatusCodes.isBlank()) {
            return Set.of();
        }

        Set<Integer> codes = new HashSet<>();
        for (String rawCode : rawStatusCodes.split(",")) {
            String code = rawCode.trim();
            if (code.isEmpty()) {
                continue;
            }
            try {
                codes.add(Integer.parseInt(code));
            } catch (NumberFormatException e) {
                api.logging().logToError("Invalid status code in exclude list: " + code);
            }
        }
        return Set.copyOf(codes);
    }

    /**
     * Hẹn giờ tính lại thống kê, gom các thay đổi liên tiếp thành một lần chạy.
     * <p>
     * {@link #updateStats()} phải quét toàn bộ bảng, nên gọi trực tiếp sau mỗi response
     * sẽ trở thành điểm nghẽn khi traffic dày. Chỉ được gọi trên EDT.
     */
    private void scheduleStatsUpdate() {
        if (statsRefreshTimer == null) {
            statsRefreshTimer = new javax.swing.Timer(300, e -> updateStats());
            statsRefreshTimer.setRepeats(false);
        }
        statsRefreshTimer.restart();
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
     * Dừng luồng nền và đóng kết nối cơ sở dữ liệu để giải phóng tài nguyên.
     */
    @Override
    public void extensionUnloaded() {
        // Chờ các thao tác ghi đang dở hoàn tất để không mất dữ liệu, nhưng không chờ vô hạn.
        dbExecutor.shutdown();
        try {
            if (!dbExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                dbExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            dbExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        databaseManager.close();
    }
}
