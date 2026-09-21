package com.example;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Kiem thu rule loai bo tham so khong can theo doi.
 */
class IgnoredParameterRulesTest {

    private final List<String> errors = new ArrayList<>();

    private IgnoredParameterRules compile(String rules) {
        return IgnoredParameterRules.compile(rules, errors::add);
    }

    @Test
    void khongCoRuleThiGiuNguyenTapThamSo() {
        IgnoredParameterRules rules = IgnoredParameterRules.empty();
        Set<String> params = Set.of("id", "utm_source");

        assertTrue(rules.isEmpty());
        assertFalse(rules.isIgnored("utm_source"));
        // Khong co gi de loc thi tra ve chinh tap dau vao, khong cap phat them.
        assertSame(params, rules.filter(params));
    }

    @Test
    void tenChinhXacDuocLoaiBo() {
        IgnoredParameterRules rules = compile("_ga");

        assertTrue(rules.isIgnored("_ga"));
        assertFalse(rules.isIgnored("_gali"));
        assertFalse(rules.isIgnored("x_ga"));
    }

    @Test
    void wildcardSaoKhopPhanDuoiTuyY() {
        IgnoredParameterRules rules = compile("utm_*");

        assertTrue(rules.isIgnored("utm_source"));
        assertTrue(rules.isIgnored("utm_"));
        assertFalse(rules.isIgnored("x_utm_source"));
    }

    @Test
    void wildcardHoiChamKhopDungMotKyTu() {
        IgnoredParameterRules rules = compile("sess?on");

        assertTrue(rules.isIgnored("session"));
        assertTrue(rules.isIgnored("sessXon"));
        // Thieu dung mot ky tu nen khong khop.
        assertFalse(rules.isIgnored("sesson"));
    }

    @Test
    void kyTuDacBietTrongTenDuocEscape() {
        // Dau cham phai duoc hieu la ky tu that, khong phai "mot ky tu bat ky" cua regex.
        IgnoredParameterRules rules = compile("a.b");

        assertTrue(rules.isIgnored("a.b"));
        assertFalse(rules.isIgnored("axb"));
    }

    @Test
    void cuPhapRegexDuocApDungNguyenVan() {
        IgnoredParameterRules rules = compile("regex:^__.*$");

        assertTrue(rules.isIgnored("__proto__"));
        assertFalse(rules.isIgnored("_proto"));
    }

    @Test
    void ruleKhopTronVenTenThamSo() {
        IgnoredParameterRules rules = compile("regex:token");

        assertTrue(rules.isIgnored("token"));
        // Khop tron ven, nen "csrf_token" khong bi loai.
        assertFalse(rules.isIgnored("csrf_token"));
    }

    @Test
    void locBoDungCacThamSoKhop() {
        IgnoredParameterRules rules = compile("utm_*\n_ga\nregex:^__.*$");

        Set<String> filtered = rules.filter(new java.util.HashSet<>(
                Set.of("id", "page", "utm_source", "utm_medium", "_ga", "__proto__")));

        assertEquals(Set.of("id", "page"), filtered);
    }

    @Test
    void dongTrongVaDongChuThichDuocBoQua() {
        IgnoredParameterRules rules = compile("# chu thich\n\n_ga\n");

        assertTrue(rules.isIgnored("_ga"));
        assertTrue(errors.isEmpty(), "Dong chu thich khong duoc coi la rule sai");
    }

    @Test
    void regexSaiCuPhapDuocBaoLoiVaBoQua() {
        IgnoredParameterRules rules = compile("regex:[unclosed");

        assertEquals(1, errors.size());
        assertTrue(rules.isEmpty());
    }

    @Test
    void chuoiRongTraVeRuleRong() {
        assertTrue(IgnoredParameterRules.compile(null, errors::add).isEmpty());
        assertTrue(IgnoredParameterRules.compile("   ", errors::add).isEmpty());
        assertTrue(errors.isEmpty());
    }
}
