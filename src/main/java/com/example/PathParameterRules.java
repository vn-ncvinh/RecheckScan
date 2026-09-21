package com.example;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Biên dịch và áp dụng các rule chuẩn hoá path parameter động.
 * <p>
 * Lớp này thuần logic, không phụ thuộc Montoya API: mọi lỗi cú pháp rule được báo ra
 * qua {@code errorLogger}. Nhờ vậy phần dễ sai nhất của extension có thể unit test trực tiếp.
 * <p>
 * Đối tượng là bất biến (immutable) nên an toàn khi chia sẻ giữa EDT và các luồng HTTP của Burp.
 */
final class PathParameterRules {
    /**
     * Thể hiện dùng chung cho trường hợp không có rule nào.
     */
    private static final PathParameterRules EMPTY = new PathParameterRules(List.of(), List.of());

    /**
     * Các rule thay thế segment động bằng placeholder.
     */
    private final List<PathParameterRule> rules;
    /**
     * Các regex đánh dấu path được giữ nguyên, không chuẩn hoá.
     */
    private final List<Pattern> ignorePatterns;

    private PathParameterRules(List<PathParameterRule> rules, List<Pattern> ignorePatterns) {
        this.rules = rules;
        this.ignorePatterns = ignorePatterns;
    }

    static PathParameterRules empty() {
        return EMPTY;
    }

    /**
     * Biên dịch cấu hình rule do người dùng nhập.
     *
     * @param rulesText       Mỗi dòng một rule dạng {@code {id}=number:19}. Dòng trống hoặc bắt đầu bằng '#' bị bỏ qua.
     * @param ignoreRulesText Mỗi dòng một regex; path khớp sẽ không bị chuẩn hoá.
     * @param errorLogger     Nơi nhận thông báo cho các rule sai cú pháp.
     * @return Một đối tượng bất biến sẵn sàng dùng, không bao giờ null.
     */
    static PathParameterRules compile(String rulesText, String ignoreRulesText, Consumer<String> errorLogger) {
        List<PathParameterRule> compiledRules = compileRules(rulesText, errorLogger);
        List<Pattern> compiledIgnorePatterns = compileIgnoreRules(ignoreRulesText, errorLogger);
        if (compiledRules.isEmpty() && compiledIgnorePatterns.isEmpty()) {
            return EMPTY;
        }
        return new PathParameterRules(List.copyOf(compiledRules), List.copyOf(compiledIgnorePatterns));
    }

    /**
     * @return true khi không có rule chuẩn hoá nào, tức {@link #normalize(String)} luôn trả về path gốc.
     */
    boolean isEmpty() {
        return rules.isEmpty();
    }

    /**
     * Chuẩn hoá các segment động trong URL path theo rule người dùng cấu hình.
     * Ví dụ: /api/report/1684050854912458752/list -> /api/report/{id}/list.
     */
    String normalize(String path) {
        if (path == null || path.isBlank() || rules.isEmpty() || isIgnored(path)) {
            return path;
        }

        String[] segments = path.split("/", -1);
        boolean changed = false;
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            if (segment.isEmpty()) {
                continue;
            }
            for (PathParameterRule rule : rules) {
                if (rule.matches(segment)) {
                    segments[i] = rule.placeholder();
                    changed = true;
                    break;
                }
            }
        }
        return changed ? String.join("/", segments) : path;
    }

    /**
     * @return true nếu path khớp một trong các regex loại trừ, khi đó path được giữ nguyên.
     */
    boolean isIgnored(String path) {
        return ignorePatterns.stream().anyMatch(pattern -> pattern.matcher(path).find());
    }

    private static List<PathParameterRule> compileRules(String rulesText, Consumer<String> errorLogger) {
        List<PathParameterRule> compiledRules = new ArrayList<>();
        if (rulesText == null || rulesText.isBlank()) {
            return compiledRules;
        }

        for (String rawLine : rulesText.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            int separatorIndex = line.indexOf('=');
            if (separatorIndex <= 0 || separatorIndex == line.length() - 1) {
                errorLogger.accept("Invalid path parameter rule: " + line);
                continue;
            }

            String placeholder = normalizePlaceholder(line.substring(0, separatorIndex).trim());
            String spec = line.substring(separatorIndex + 1).trim();
            Pattern pattern = compilePattern(spec, errorLogger);
            if (pattern != null) {
                compiledRules.add(new PathParameterRule(placeholder, pattern));
            }
        }
        return compiledRules;
    }

    private static List<Pattern> compileIgnoreRules(String rulesText, Consumer<String> errorLogger) {
        List<Pattern> compiledPatterns = new ArrayList<>();
        if (rulesText == null || rulesText.isBlank()) {
            return compiledPatterns;
        }

        for (String rawLine : rulesText.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            try {
                compiledPatterns.add(Pattern.compile(line));
            } catch (PatternSyntaxException e) {
                errorLogger.accept("Invalid ignore path parameter regex rule: " + line + " - " + e.getMessage());
            }
        }
        return compiledPatterns;
    }

    private static String normalizePlaceholder(String placeholder) {
        if (placeholder.startsWith("{") && placeholder.endsWith("}")) {
            return placeholder;
        }
        return "{" + placeholder.replace("{", "").replace("}", "") + "}";
    }

    private static Pattern compilePattern(String spec, Consumer<String> errorLogger) {
        String lowerSpec = spec.toLowerCase(Locale.ROOT);
        if (lowerSpec.startsWith("regex:")) {
            try {
                return Pattern.compile(spec.substring("regex:".length()));
            } catch (PatternSyntaxException e) {
                errorLogger.accept("Invalid path parameter regex rule: " + spec + " - " + e.getMessage());
                return null;
            }
        }

        String[] parts = lowerSpec.split(":", 2);
        String type = parts[0].trim();
        Integer length = null;
        if (parts.length == 2 && !parts[1].isBlank()) {
            try {
                length = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException e) {
                errorLogger.accept("Invalid path parameter length in rule: " + spec);
                return null;
            }
            if (length <= 0) {
                errorLogger.accept("Path parameter length must be positive in rule: " + spec);
                return null;
            }
        }

        String quantifier = length == null ? "+" : "{" + length + "}";
        return switch (type) {
            case "number", "numeric", "digits" -> Pattern.compile("[0-9]" + quantifier);
            case "hex" -> Pattern.compile("[0-9a-fA-F]" + quantifier);
            case "uuid" -> Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
            case "alnum", "alpha_numeric" -> Pattern.compile("[0-9a-zA-Z]" + quantifier);
            default -> {
                errorLogger.accept("Unsupported path parameter rule type: " + spec);
                yield null;
            }
        };
    }
}
