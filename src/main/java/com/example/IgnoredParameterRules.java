package com.example;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

/**
 * Biên dịch và áp dụng các rule loại bỏ tham số không cần theo dõi.
 * <p>
 * Tham số khớp rule sẽ bị loại ngay tại {@code extractParameters}, tức không bao giờ
 * được ghi vào CSDL và cũng không được tính là "chưa quét". Dùng cho các tham số rác
 * như {@code utm_*}, {@code _ga}, {@code timestamp}.
 * <p>
 * Mỗi dòng là một rule, hỗ trợ ba dạng:
 * <ul>
 *   <li>tên chính xác: {@code _ga}</li>
 *   <li>wildcard: {@code utm_*}, {@code sess?on}</li>
 *   <li>regex tự viết: {@code regex:^__.*$}</li>
 * </ul>
 * Rule luôn so khớp <b>trọn vẹn</b> tên tham số.
 * <p>
 * Lớp này thuần logic (không phụ thuộc Montoya API) nên unit test được trực tiếp,
 * và bất biến nên an toàn khi chia sẻ giữa EDT và các luồng HTTP của Burp.
 */
final class IgnoredParameterRules {
    private static final IgnoredParameterRules EMPTY = new IgnoredParameterRules(List.of());

    private final List<Pattern> patterns;

    private IgnoredParameterRules(List<Pattern> patterns) {
        this.patterns = patterns;
    }

    static IgnoredParameterRules empty() {
        return EMPTY;
    }

    /**
     * @param rulesText   Mỗi dòng một rule. Dòng trống hoặc bắt đầu bằng '#' bị bỏ qua.
     * @param errorLogger Nơi nhận thông báo cho các rule sai cú pháp.
     * @return Một đối tượng bất biến sẵn sàng dùng, không bao giờ null.
     */
    static IgnoredParameterRules compile(String rulesText, Consumer<String> errorLogger) {
        if (rulesText == null || rulesText.isBlank()) {
            return EMPTY;
        }

        List<Pattern> compiledPatterns = new ArrayList<>();
        for (String rawLine : rulesText.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            Pattern pattern = compilePattern(line, errorLogger);
            if (pattern != null) {
                compiledPatterns.add(pattern);
            }
        }
        return compiledPatterns.isEmpty() ? EMPTY : new IgnoredParameterRules(List.copyOf(compiledPatterns));
    }

    boolean isEmpty() {
        return patterns.isEmpty();
    }

    /**
     * @return true nếu tên tham số khớp trọn vẹn một trong các rule.
     */
    boolean isIgnored(String parameterName) {
        if (parameterName == null || patterns.isEmpty()) {
            return false;
        }
        return patterns.stream().anyMatch(pattern -> pattern.matcher(parameterName).matches());
    }

    /**
     * Loại khỏi tập hợp mọi tham số khớp rule.
     *
     * @return Tập hợp đã lọc; trả về chính tham số đầu vào khi không có gì để lọc.
     */
    Set<String> filter(Set<String> parameterNames) {
        if (parameterNames == null || parameterNames.isEmpty() || patterns.isEmpty()) {
            return parameterNames;
        }

        return parameterNames.stream()
                .filter(parameterName -> !isIgnored(parameterName))
                .collect(Collectors.toCollection(HashSet::new));
    }

    private static Pattern compilePattern(String spec, Consumer<String> errorLogger) {
        if (spec.toLowerCase(Locale.ROOT).startsWith("regex:")) {
            try {
                return Pattern.compile(spec.substring("regex:".length()));
            } catch (PatternSyntaxException e) {
                errorLogger.accept("Invalid ignored parameter regex rule: " + spec + " - " + e.getMessage());
                return null;
            }
        }

        try {
            return Pattern.compile(wildcardToRegex(spec));
        } catch (PatternSyntaxException e) {
            errorLogger.accept("Invalid ignored parameter rule: " + spec + " - " + e.getMessage());
            return null;
        }
    }

    /**
     * Dịch cú pháp wildcard sang regex: '*' thành ".*", '?' thành ".".
     * Mọi ký tự còn lại được escape để tên tham số chứa ký tự đặc biệt
     * không bị hiểu nhầm thành cú pháp regex.
     */
    private static String wildcardToRegex(String spec) {
        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < spec.length(); i++) {
            char ch = spec.charAt(i);
            if (ch == '*') {
                regex.append(".*");
            } else if (ch == '?') {
                regex.append('.');
            } else {
                regex.append(Pattern.quote(String.valueOf(ch)));
            }
        }
        return regex.toString();
    }
}
