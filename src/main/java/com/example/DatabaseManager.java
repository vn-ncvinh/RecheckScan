package com.example;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;

public class DatabaseManager {
    private final MontoyaApi api;
    private Connection connection;
    private String dbPath;

    public DatabaseManager(MontoyaApi api) {
        this.api = api;
    }

    public void initialize(String savedOutputPath) {
        this.dbPath = getDbPath(savedOutputPath);
        try {
            Class.forName("org.sqlite.JDBC");
            File dbFile = new File(dbPath);
            if (!dbFile.getParentFile().exists()) {
                dbFile.getParentFile().mkdirs();
            }
            connection = DriverManager.getConnection("jdbc:sqlite:" + this.dbPath);
            api.logging().logToOutput("Successfully connected to SQLite database: " + this.dbPath);
            createTableIfNotExists();
        } catch (SQLException | ClassNotFoundException e) {
            api.logging().logToError("Failed to initialize SQLite database: " + e.getMessage(), e);
        }
    }

    private String getDbPath(String savedOutputPath) {
        if (savedOutputPath != null && !savedOutputPath.isBlank()) {
            String path = savedOutputPath.toLowerCase().endsWith(".csv")
                    ? savedOutputPath.substring(0, savedOutputPath.length() - 4)
                    : savedOutputPath;
            return path.toLowerCase().endsWith(".db") ? path : path + ".db";
        }
        return new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api.db").getAbsolutePath();
    }

    private void createTableIfNotExists() throws SQLException {
        String sql = """
            CREATE TABLE IF NOT EXISTS api_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                unscanned_params TEXT,
                scanned_params TEXT,
                is_scanned BOOLEAN DEFAULT 0,
                is_rejected BOOLEAN DEFAULT 0,
                is_bypassed BOOLEAN DEFAULT 0,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, path, method)
            );
            """;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    public List<Object[]> loadApiData() {
        List<Object[]> rows = new ArrayList<>();
        String sql = "SELECT id, method, host, path, unscanned_params, scanned_params, is_scanned, is_rejected, is_bypassed FROM api_log ORDER BY id DESC";
        try (Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                String unscanned = rs.getString("unscanned_params");
                String scanned = rs.getString("scanned_params");
                StringBuilder note = new StringBuilder();
                if (unscanned != null && !unscanned.isEmpty()) {
                    note.append("Unscanned: [").append(unscanned.replace("|", ", ")).append("] ");
                }
                if (scanned != null && !scanned.isEmpty()) {
                    note.append("Scanned: [").append(scanned.replace("|", ", ")).append("]");
                }

                rows.add(new Object[]{
                        rs.getString("method"),
                        rs.getString("host"),
                        rs.getString("path"),
                        note.toString().trim(),
                        rs.getBoolean("is_scanned"),
                        rs.getBoolean("is_rejected"),
                        rs.getBoolean("is_bypassed"),
                        rs.getInt("id")
                });
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to load API data from database: " + e.getMessage(), e);
        }
        return rows;
    }

    public synchronized void insertOrUpdateApi(String method, String host, String path, Set<String> requestParams) {
        String selectSql = "SELECT unscanned_params, scanned_params FROM api_log WHERE host = ? AND path = ? AND method = ?";
        try (PreparedStatement selectStmt = connection.prepareStatement(selectSql)) {
            selectStmt.setString(1, host);
            selectStmt.setString(2, path);
            selectStmt.setString(3, method);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next()) {
                Set<String> unscannedSet = stringToSet(rs.getString("unscanned_params"));
                Set<String> scannedSet = stringToSet(rs.getString("scanned_params"));
                Set<String> knownParams = new HashSet<>(unscannedSet);
                knownParams.addAll(scannedSet);
                Set<String> newDiscoveredParams = new HashSet<>(requestParams);
                newDiscoveredParams.removeAll(knownParams);

                if (!newDiscoveredParams.isEmpty()) {
                    unscannedSet.addAll(newDiscoveredParams);
                    String updatedUnscannedParams = setToString(unscannedSet);
                    String updateSql = "UPDATE api_log SET unscanned_params = ?, is_scanned = 0, last_seen = CURRENT_TIMESTAMP WHERE host = ? AND path = ? AND method = ?";
                    try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                        updateStmt.setString(1, updatedUnscannedParams);
                        updateStmt.setString(2, host);
                        updateStmt.setString(3, path);
                        updateStmt.setString(4, method);
                        updateStmt.executeUpdate();
                    }
                }
            } else {
                String paramsStr = setToString(requestParams);
                String insertSql = "INSERT INTO api_log (method, host, path, unscanned_params) VALUES (?, ?, ?, ?)";
                try (PreparedStatement insertStmt = connection.prepareStatement(insertSql)) {
                    insertStmt.setString(1, method);
                    insertStmt.setString(2, host);
                    insertStmt.setString(3, path);
                    insertStmt.setString(4, paramsStr);
                    insertStmt.executeUpdate();
                }
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during insert/update API: " + e.getMessage(), e);
        }
    }
    
    public synchronized boolean processScannedParameters(String method, String host, String path, Set<String> scannerParams) {
        String selectSql = "SELECT unscanned_params, scanned_params FROM api_log WHERE host = ? AND path = ? AND method = ?";
        try (PreparedStatement selectStmt = connection.prepareStatement(selectSql)) {
            selectStmt.setString(1, host);
            selectStmt.setString(2, path);
            selectStmt.setString(3, method);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next()) {
                Set<String> unscannedDbSet = stringToSet(rs.getString("unscanned_params"));
                if (unscannedDbSet.isEmpty()) return false;

                Set<String> newlyScannedParams = new HashSet<>(scannerParams);
                newlyScannedParams.retainAll(unscannedDbSet);
                if (newlyScannedParams.isEmpty()) return false;

                Set<String> scannedDbSet = stringToSet(rs.getString("scanned_params"));
                unscannedDbSet.removeAll(newlyScannedParams);
                scannedDbSet.addAll(newlyScannedParams);

                String updateSql = "UPDATE api_log SET unscanned_params = ?, scanned_params = ?, is_scanned = ?, last_seen = CURRENT_TIMESTAMP WHERE host = ? AND path = ? AND method = ?";
                try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                    updateStmt.setString(1, setToString(unscannedDbSet));
                    updateStmt.setString(2, setToString(scannedDbSet));
                    updateStmt.setBoolean(3, unscannedDbSet.isEmpty());
                    updateStmt.setString(4, host);
                    updateStmt.setString(5, path);
                    updateStmt.setString(6, method);
                    updateStmt.executeUpdate();
                    return true;
                }
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during processScannedParameters: " + e.getMessage(), e);
        }
        return false;
    }

    public synchronized boolean autoBypassApi(String method, String host, String path) {
        String upsertSql = """
            INSERT INTO api_log (method, host, path, unscanned_params, scanned_params, is_bypassed)
            VALUES (?, ?, ?, '', '', 1)
            ON CONFLICT(host, path, method) DO UPDATE SET
                is_bypassed = CASE
                    WHEN api_log.is_scanned = 0 AND api_log.is_rejected = 0 THEN 1
                    ELSE api_log.is_bypassed
                END,
                last_seen = CURRENT_TIMESTAMP
            """;
        try (PreparedStatement stmt = connection.prepareStatement(upsertSql)) {
            stmt.setString(1, method);
            stmt.setString(2, host);
            stmt.setString(3, path);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            api.logging().logToError("Error during autoBypassApi: " + e.getMessage(), e);
            return false;
        }
    }
    
    private Set<String> stringToSet(String str) {
        if (str == null || str.isBlank()) return new HashSet<>();
        return new HashSet<>(Arrays.asList(str.split("\\|")));
    }

    private String setToString(Set<String> set) {
        if (set == null || set.isEmpty()) return "";
        return set.stream().sorted().collect(Collectors.joining("|"));
    }
    
    public void updateApiStatus(int id, String columnName, boolean value) {
        if (!Arrays.asList("is_scanned", "is_rejected", "is_bypassed").contains(columnName)) {
            api.logging().logToError("Invalid column name for status update.");
            return;
        }
        String sql = String.format("UPDATE api_log SET %s = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?", columnName);
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setBoolean(1, value);
            pstmt.setInt(2, id);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            api.logging().logToError("Failed to update API status: " + e.getMessage(), e);
        }
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                api.logging().logToOutput("Database connection closed.");
            }
        } catch (SQLException e) {
            api.logging().logToError("Error closing database connection: " + e.getMessage(), e);
        }
    }
    
    public Object[] getApiStatus(String method, String host, String path) {
        String sql = "SELECT is_scanned, is_rejected, is_bypassed FROM api_log WHERE host = ? AND path = ? AND method = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, path);
            stmt.setString(3, method);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new Object[]{rs.getBoolean("is_scanned"), rs.getBoolean("is_rejected"), rs.getBoolean("is_bypassed")};
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to get API status for " + host + path + ": " + e.getMessage(), e);
        }
        return null;
    }
}