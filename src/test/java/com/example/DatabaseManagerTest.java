package com.example;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Kiểm thử các hàm thuần logic của DatabaseManager: tuần tự hoá tham số và phân giải đường dẫn CSDL.
 */
class DatabaseManagerTest {

    @Test
    void chuoiRongHoacNullTraVeSetRong() {
        assertTrue(DatabaseManager.stringToSet(null).isEmpty());
        assertTrue(DatabaseManager.stringToSet("").isEmpty());
        assertTrue(DatabaseManager.stringToSet("   ").isEmpty());
    }

    @Test
    void setRongHoacNullTraVeChuoiRong() {
        assertEquals("", DatabaseManager.setToString(null));
        assertEquals("", DatabaseManager.setToString(Set.of()));
    }

    @Test
    void setDuocTuanTuHoaTheoThuTuAlphabet() {
        Set<String> params = new LinkedHashSet<>();
        params.add("zeta");
        params.add("alpha");
        params.add("Mike");

        // Sắp xếp theo thứ tự tự nhiên của String: chữ hoa đứng trước chữ thường.
        assertEquals("Mike|alpha|zeta", DatabaseManager.setToString(params));
    }

    @Test
    void chuyenDoiKhuHoiGiuNguyenTapThamSo() {
        Set<String> params = Set.of("id", "page", "sort_by");

        assertEquals(params, DatabaseManager.stringToSet(DatabaseManager.setToString(params)));
    }

    @Test
    void duongDanCsvCuDuocChuyenSangDb() {
        assertEquals("C:/burp/scan_api.db", DatabaseManager.getDbPath("C:/burp/scan_api.csv"));
    }

    @Test
    void duongDanThieuDuoiDuocThemDb() {
        assertEquals("C:/burp/scan_api.db", DatabaseManager.getDbPath("C:/burp/scan_api"));
    }

    @Test
    void duongDanDaCoDuoiDbGiuNguyen() {
        assertEquals("C:/burp/scan_api.DB", DatabaseManager.getDbPath("C:/burp/scan_api.DB"));
    }

    @Test
    void duongDanRongDungMacDinhTrongThuMucTam() {
        String expected = new File(System.getProperty("java.io.tmpdir"), "RecheckScan/scan_api.db").getAbsolutePath();

        assertEquals(expected, DatabaseManager.getDbPath(null));
        assertEquals(expected, DatabaseManager.getDbPath("   "));
    }
}
