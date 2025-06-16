package com.example;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.HashSet;
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
                params TEXT,
                is_scanned BOOLEAN DEFAULT 0,
                is_rejected BOOLEAN DEFAULT 0,
                is_bypassed BOOLEAN DEFAULT 0,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, path)
            );
            """;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    public List<Object[]> loadApiData() {
        List<Object[]> rows = new ArrayList<>();
        String sql = "SELECT id, method, host, path, params, is_scanned, is_rejected, is_bypassed FROM api_log ORDER BY id DESC";
        try (Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                rows.add(new Object[]{
                        rs.getString("method"),
                        rs.getString("host"),
                        rs.getString("path"),
                        rs.getString("params") != null ? rs.getString("params").replace("|", ", ") : "",
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

    public synchronized Object[] insertOrUpdateApi(String method, String host, String path, Set<String> newParamsSet) {
        String newParamsStr = newParamsSet.stream().sorted().collect(Collectors.joining("|"));
        String upsertSql = """
            INSERT INTO api_log (method, host, path, params) VALUES (?, ?, ?, ?)
            ON CONFLICT(host, path) DO UPDATE SET
                params=excluded.params,
                is_scanned = CASE WHEN api_log.params = excluded.params THEN api_log.is_scanned ELSE 0 END,
                last_seen=CURRENT_TIMESTAMP
            RETURNING id, method, host, path, params, is_scanned, is_rejected, is_bypassed;
            """;

        try {
            String oldParamsStr = getExistingParams(host, path);
            Set<String> oldParams = (oldParamsStr == null || oldParamsStr.isEmpty()) ? new HashSet<>() : new HashSet<>(Arrays.asList(oldParamsStr.split("\\|")));
            Set<String> addedParams = new HashSet<>(newParamsSet);
            addedParams.removeAll(oldParams);

            try (PreparedStatement upsertStmt = connection.prepareStatement(upsertSql)) {
                upsertStmt.setString(1, method);
                upsertStmt.setString(2, host);
                upsertStmt.setString(3, path);
                upsertStmt.setString(4, newParamsStr);
                
                ResultSet rs = upsertStmt.executeQuery();
                if (rs.next()) {
                    String displayNote = newParamsSet.stream().sorted().collect(Collectors.joining(", "));
                    if (!addedParams.isEmpty()) {
                        displayNote += " [new: " + addedParams.stream().sorted().collect(Collectors.joining(", ")) + "]";
                    }
                    return new Object[]{
                            rs.getString("method"),
                            rs.getString("host"),
                            rs.getString("path"),
                            displayNote,
                            rs.getBoolean("is_scanned"),
                            rs.getBoolean("is_rejected"),
                            rs.getBoolean("is_bypassed"),
                            rs.getInt("id")
                    };
                }
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during insert/update API: " + e.getMessage(), e);
        }
        return null;
    }

    private String getExistingParams(String host, String path) throws SQLException {
        String sql = "SELECT params FROM api_log WHERE host = ? AND path = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, path);
            ResultSet rs = stmt.executeQuery();
            return rs.next() ? rs.getString("params") : null;
        }
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

    public Object[] getApiStatus(String host, String path) {
        String sql = "SELECT is_scanned, is_rejected, is_bypassed FROM api_log WHERE host = ? AND path = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, path);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new Object[]{
                    rs.getBoolean("is_scanned"),
                    rs.getBoolean("is_rejected"),
                    rs.getBoolean("is_bypassed")
                };
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to get API status for " + host + path + ": " + e.getMessage(), e);
        }
        return null;
    }

    public synchronized Object[] insertOrBypassApi(String method, String host, String path) {
        String upsertSql = """
            INSERT INTO api_log (method, host, path, params, is_bypassed)
            VALUES (?, ?, ?, '', 1)
            ON CONFLICT(host, path) DO UPDATE SET
                is_bypassed = CASE
                    WHEN api_log.is_scanned = 0 AND api_log.is_rejected = 0 THEN 1
                    ELSE api_log.is_bypassed
                END,
                last_seen = CURRENT_TIMESTAMP
            RETURNING id, method, host, path, params, is_scanned, is_rejected, is_bypassed;
            """;
        try (PreparedStatement upsertStmt = connection.prepareStatement(upsertSql)) {
            upsertStmt.setString(1, method);
            upsertStmt.setString(2, host);
            upsertStmt.setString(3, path);
            ResultSet rs = upsertStmt.executeQuery();
            if (rs.next()) {
                return new Object[]{
                        rs.getString("method"),
                        rs.getString("host"),
                        rs.getString("path"),
                        "",
                        rs.getBoolean("is_scanned"),
                        rs.getBoolean("is_rejected"),
                        rs.getBoolean("is_bypassed"),
                        rs.getInt("id")
                };
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during insert/bypass API: " + e.getMessage(), e);
        }
        return null;
    }
    
    public Integer findIdByHostPath(String host, String path) {
        String sql = "SELECT id FROM api_log WHERE host = ? AND path = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, path);
            ResultSet rs = stmt.executeQuery();
            return rs.next() ? rs.getInt("id") : null;
        } catch (SQLException e) {
            api.logging().logToError("Failed to find API ID for " + host + path + ": " + e.getMessage(), e);
            return null;
        }
    }

    /**
     * Lấy trạng thái quét và danh sách tham số hiện tại của một API.
     * @return Mảng Object chứa {is_scanned (Boolean), params (String)}, hoặc null nếu không tìm thấy.
     */
    public Object[] getApiState(String host, String path) {
        String sql = "SELECT is_scanned, params FROM api_log WHERE host = ? AND path = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, path);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new Object[]{ rs.getBoolean("is_scanned"), rs.getString("params") };
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to get API state for " + host + path + ": " + e.getMessage(), e);
        }
        return null;
    }
}