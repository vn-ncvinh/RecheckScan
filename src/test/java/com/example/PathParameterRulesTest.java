package com.example;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Kiểm thử phần biên dịch và áp dụng rule chuẩn hoá path parameter.
 */
class PathParameterRulesTest {

    /**
     * Thu lại các thông báo lỗi để khẳng định rule sai cú pháp được báo ra đúng chỗ.
     */
    private final List<String> errors = new ArrayList<>();

    private PathParameterRules compile(String rules) {
        return PathParameterRules.compile(rules, "", errors::add);
    }

    @Test
    void khongCoRuleThiGiuNguyenPath() {
        PathParameterRules rules = PathParameterRules.empty();

        assertTrue(rules.isEmpty());
        assertEquals("/api/report/12345/list", rules.normalize("/api/report/12345/list"));
    }

    @Test
    void ruleNumberCoDoDaiChiKhopDungSoKyTu() {
        PathParameterRules rules = compile("{id}=number:19");

        assertEquals("/api/report/{id}/list", rules.normalize("/api/report/1684050854912458752/list"));
        // Segment 4 chữ số không đủ 19 ký tự nên phải giữ nguyên.
        assertEquals("/api/v1/2024/list", rules.normalize("/api/v1/2024/list"));
        assertTrue(errors.isEmpty());
    }

    @Test
    void ruleKhopTheoToanBoSegmentChuKhongPhaiMotPhan() {
        PathParameterRules rules = compile("{id}=number");

        // "v1" khong phai toan so nen giu nguyen; chi segment "2" bi thay the.
        // Day cung la canh bao: rule number khong kem do dai se nuot ca so trang, so phien ban.
        assertEquals("/v1/{id}", rules.normalize("/v1/2"));
    }

    @Test
    void ruleUuidVaHexHoatDongDoiVoiSegmentTuongUng() {
        PathParameterRules rules = compile("{uuid}=uuid\n{hash}=hex:32");

        assertEquals("/users/{uuid}", rules.normalize("/users/3f2504e0-4f89-11d3-9a0c-0305e82c3301"));
        assertEquals("/files/{hash}", rules.normalize("/files/d41d8cd98f00b204e9800998ecf8427e"));
    }

    @Test
    void ruleRegexTuyChinhDuocApDungNguyenVan() {
        // Regex doi hoi it nhat hai dau gach noi nen chi khop dung segment slug.
        PathParameterRules rules = compile("{slug}=regex:[a-z0-9]+(-[a-z0-9]+){2,}");

        assertEquals("/blog/{slug}/comments", rules.normalize("/blog/hello-world-2024/comments"));
    }

    @Test
    void regexQuaRongSeNuotMoiSegmentKhop() {
        // Chinh la vi du dang hien trong phan huong dan o tab Settings:
        // [a-z0-9-]+ khop ca "blog" lan "comments", khong chi rieng slug.
        PathParameterRules rules = compile("{slug}=regex:[a-z0-9-]+");

        assertEquals("/{slug}/{slug}/{slug}", rules.normalize("/blog/hello-world-2024/comments"));
    }

    @Test
    void ruleDauTienKhopSeThangVaSegmentRongDuocBoQua() {
        // {hex} đứng trước nên phải thắng với segment toàn chữ số.
        PathParameterRules rules = compile("{hex}=hex:4\n{id}=number:4");

        assertEquals("/{hex}/", rules.normalize("/1234/"));
    }

    @Test
    void pathTrongHoacNullDuocTraVeNguyenTrang() {
        PathParameterRules rules = compile("{id}=number:4");

        assertEquals(null, rules.normalize(null));
        assertEquals("", rules.normalize(""));
        assertEquals("   ", rules.normalize("   "));
    }

    @Test
    void placeholderTuDongDuocBocTrongNgoacNhon() {
        PathParameterRules rules = compile("id=number:4");

        assertEquals("/api/{id}", rules.normalize("/api/1234"));
    }

    @Test
    void dongTrongVaDongChuThichDuocBoQua() {
        PathParameterRules rules = compile("# đây là chú thích\n\n{id}=number:4\n");

        assertEquals("/api/{id}", rules.normalize("/api/1234"));
        assertTrue(errors.isEmpty(), "Dòng chú thích không được coi là rule sai");
    }

    @Test
    void ruleSaiCuPhapDuocBaoLoiVaBoQua() {
        PathParameterRules rules = compile("khong-co-dau-bang\n{id}=unsupported\n{bad}=number:0\n{nan}=number:abc\n{re}=regex:[unclosed");

        assertTrue(rules.isEmpty(), "Không rule nào hợp lệ nên không được chuẩn hoá gì");
        assertEquals(5, errors.size(), "Mỗi rule sai phải sinh đúng một thông báo lỗi");
    }

    @Test
    void ignoreRuleGiuNguyenPathKhop() {
        PathParameterRules rules = PathParameterRules.compile(
                "{id}=number:4", "^/api/reports/[0-9]{4}/summary$", errors::add);

        assertTrue(rules.isIgnored("/api/reports/2024/summary"));
        assertEquals("/api/reports/2024/summary", rules.normalize("/api/reports/2024/summary"));
        // Path không khớp regex loại trừ thì vẫn được chuẩn hoá bình thường.
        assertFalse(rules.isIgnored("/api/reports/2024/detail"));
        assertEquals("/api/reports/{id}/detail", rules.normalize("/api/reports/2024/detail"));
    }

    @Test
    void ignoreRuleSaiCuPhapDuocBaoLoiVaBoQua() {
        PathParameterRules rules = PathParameterRules.compile("{id}=number:4", "[unclosed", errors::add);

        assertEquals(1, errors.size());
        assertFalse(rules.isIgnored("/api/1234"));
    }
}
