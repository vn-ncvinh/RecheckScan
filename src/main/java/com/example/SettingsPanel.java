// SettingsPanel.java
package com.example;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Lớp này là một "Factory" để tạo ra panel cho tab "Settings".
 * Nó chỉ chịu trách nhiệm sắp xếp các thành phần giao diện (UI components)
 * và không chứa bất kỳ logic nghiệp vụ nào. Các components (như JTextArea, JButton)
 * được tạo và quản lý trong lớp chính (RecheckScanApiExtension).
 */
public class SettingsPanel {

    /**
     * Phương thức tĩnh tạo và trả về một JPanel đã được cấu hình hoàn chỉnh cho tab Settings.
     * @param extensionArea Vùng nhập các extension cần loại trừ.
     * @param outputPathField Trường nhập đường dẫn lưu file log/db.
     * @param browseButton Nút để mở cửa sổ chọn file.
     * @param highlightCheckBox Checkbox để bật/tắt highlight.
     * @param noteCheckBox Checkbox để bật/tắt thêm note.
     * @param autoBypassCheckBox Checkbox để bật/tắt tự động bypass.
     * @param autoAnnotateHistoryCheckBox Checkbox để bật/tắt tự động sửa highlight/note trong Proxy history.
     * @param annotationBatchField Ô nhập số API tối thiểu trong hàng chờ để chạy một lượt quét.
     * @param applyButton Nút để áp dụng và lưu cài đặt.
     * @param totalLbl, scannedLbl, etc. Các nhãn để hiển thị thống kê.
     * @param excludeStatusCodesField Trường nhập các status code cần loại trừ.
     * @param ignorePathParameterRulesArea Vùng nhập các regex path không áp dụng rule parameter.
     * @param ignoreParamsArea Vùng nhập các tham số cần bỏ qua khi ghi nhận/quét.
     * @return Một JPanel chứa toàn bộ giao diện của tab Settings.
     */
    public static JPanel create(
            JTextArea  extensionArea,
            JTextField outputPathField,
            JButton    browseButton,
            JCheckBox  highlightCheckBox,
            JCheckBox  noteCheckBox,
            JCheckBox  autoBypassCheckBox,
            JCheckBox  autoAnnotateHistoryCheckBox,
            JTextField annotationBatchField,
            JButton    applyButton,
            JLabel     totalLbl,
            JLabel     scannedLbl,
            JLabel     rejectedLbl,
            JLabel     bypassLbl,
            JLabel     unverifiedLbl,
            JTextField excludeStatusCodesField,
            JTextArea  pathParameterRulesArea,
            JTextArea  ignorePathParameterRulesArea,
            JTextArea  ignoreParamsArea) {

        /* ========= PANEL GỐC (ROOT) ========= */
        JPanel settingsPanel = new JPanel();
        // Sử dụng BorderLayout để chia panel thành các khu vực CENTER, EAST, SOUTH.
        settingsPanel.setLayout(new BorderLayout(10, 10));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        /* ========= PANEL TRUNG TÂM (CENTER) - Chứa các điều khiển chính ========= */
        JPanel centerPanel = new JPanel();
        // BoxLayout theo trục Y để các nhóm panel xếp chồng lên nhau theo chiều dọc.
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));

        // --- Nhóm Cài đặt Project ---
        JPanel projectSettingsPanel = new JPanel();
        projectSettingsPanel.setLayout(new BoxLayout(projectSettingsPanel, BoxLayout.Y_AXIS));
        projectSettingsPanel.setBorder(createTitledBorder("Project Settings")); // Tạo đường viền có tiêu đề

        // Panel cho đường dẫn output và nút Browse
        JPanel outputPathPanel = new JPanel(new BorderLayout(5, 0));
        outputPathPanel.add(new JLabel("Log/DB Output Path: "), BorderLayout.WEST);
        outputPathPanel.add(outputPathField, BorderLayout.CENTER);
        outputPathPanel.add(browseButton, BorderLayout.EAST);
        // Giới hạn chiều cao tối đa để không bị giãn ra quá lớn.
        outputPathPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, outputPathField.getPreferredSize().height));
        outputPathPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(outputPathPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho Exclude Extensions
        JPanel excludeExtensionPanel = new JPanel(new BorderLayout(5, 0));
        excludeExtensionPanel.add(new JLabel("Exclude Extensions (comma separated): "), BorderLayout.WEST);
        extensionArea.setRows(1);
        JScrollPane extScroll = new JScrollPane(extensionArea);
        extScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, extensionArea.getPreferredSize().height + 10));
        extScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        excludeExtensionPanel.add(extScroll, BorderLayout.CENTER);
        excludeExtensionPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, excludeExtensionPanel.getPreferredSize().height));
        excludeExtensionPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(excludeExtensionPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho Exclude Status Codes
        JPanel excludeStatusCodePanel = new JPanel(new BorderLayout(5, 0));
        excludeStatusCodePanel.add(new JLabel("Exclude Status Codes (comma separated): "), BorderLayout.WEST);
        excludeStatusCodePanel.add(excludeStatusCodesField, BorderLayout.CENTER);
        excludeStatusCodePanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, excludeStatusCodesField.getPreferredSize().height));
        excludeStatusCodePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(excludeStatusCodePanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho rule nhận diện path parameter động
        JPanel pathParameterRulesPanel = new JPanel(new BorderLayout(5, 0));
        pathParameterRulesPanel.add(new JLabel("URL Path Parameter Rules: "), BorderLayout.WEST);
        pathParameterRulesArea.setRows(3);
        pathParameterRulesArea.setToolTipText("One rule per line.");
        JScrollPane pathRuleScroll = new JScrollPane(pathParameterRulesArea);
        JLabel pathRuleHelpLabel = new JLabel("One rule per line. Examples: {id}=number:19, {uuid}=uuid, {hash}=hex:32, {slug}=regex:[a-z0-9-]+");
        pathRuleHelpLabel.setFont(pathRuleHelpLabel.getFont().deriveFont(Font.PLAIN, 11f));
        pathRuleHelpLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel pathRuleInputPanel = new JPanel(new BorderLayout(0, 3));
        pathRuleInputPanel.add(pathRuleScroll, BorderLayout.CENTER);
        pathRuleInputPanel.add(pathRuleHelpLabel, BorderLayout.SOUTH);
        pathParameterRulesPanel.add(pathRuleInputPanel, BorderLayout.CENTER);
        pathParameterRulesPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, pathParameterRulesPanel.getPreferredSize().height));
        pathParameterRulesPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(pathParameterRulesPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho rule bỏ qua normalize path parameter
        JPanel ignorePathParameterRulesPanel = new JPanel(new BorderLayout(5, 0));
        ignorePathParameterRulesPanel.add(new JLabel("Ignore URL Path Parameter Rules: "), BorderLayout.WEST);
        ignorePathParameterRulesArea.setRows(3);
        ignorePathParameterRulesArea.setToolTipText("One regex per line. Matching paths will not be normalized by URL Path Parameter Rules.");
        JScrollPane ignorePathRuleScroll = new JScrollPane(ignorePathParameterRulesArea);
        JLabel ignorePathRuleHelpLabel = new JLabel("One regex per line. Example: ^/api/reports/[0-9]{4}/summary$");
        ignorePathRuleHelpLabel.setFont(ignorePathRuleHelpLabel.getFont().deriveFont(Font.PLAIN, 11f));
        ignorePathRuleHelpLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel ignorePathRuleInputPanel = new JPanel(new BorderLayout(0, 3));
        ignorePathRuleInputPanel.add(ignorePathRuleScroll, BorderLayout.CENTER);
        ignorePathRuleInputPanel.add(ignorePathRuleHelpLabel, BorderLayout.SOUTH);
        ignorePathParameterRulesPanel.add(ignorePathRuleInputPanel, BorderLayout.CENTER);
        ignorePathParameterRulesPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, ignorePathParameterRulesPanel.getPreferredSize().height));
        ignorePathParameterRulesPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(ignorePathParameterRulesPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho rule bỏ qua tham số
        JPanel ignoreParamsPanel = new JPanel(new BorderLayout(5, 0));
        ignoreParamsPanel.add(new JLabel("Ignore Parameters: "), BorderLayout.WEST);
        ignoreParamsArea.setRows(3);
        ignoreParamsArea.setToolTipText("One parameter per line. Matching parameters are never tracked and are removed from the database on Apply.");
        JScrollPane ignoreParamsScroll = new JScrollPane(ignoreParamsArea);
        JLabel ignoreParamsHelpLabel = new JLabel("One per line, exact name (case-insensitive) or regex:<pattern>. Examples: _csrf, timestamp, regex:^utm_.*$");
        ignoreParamsHelpLabel.setFont(ignoreParamsHelpLabel.getFont().deriveFont(Font.PLAIN, 11f));
        ignoreParamsHelpLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel ignoreParamsInputPanel = new JPanel(new BorderLayout(0, 3));
        ignoreParamsInputPanel.add(ignoreParamsScroll, BorderLayout.CENTER);
        ignoreParamsInputPanel.add(ignoreParamsHelpLabel, BorderLayout.SOUTH);
        ignoreParamsPanel.add(ignoreParamsInputPanel, BorderLayout.CENTER);
        ignoreParamsPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, ignoreParamsPanel.getPreferredSize().height));
        ignoreParamsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(ignoreParamsPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        centerPanel.add(projectSettingsPanel);
        centerPanel.add(Box.createRigidArea(new Dimension(0, 10))); // Thêm khoảng trống giữa các nhóm

        // --- Nhóm Controls ---
        JPanel controlsPanel = new JPanel();
        controlsPanel.setLayout(new BoxLayout(controlsPanel, BoxLayout.Y_AXIS));
        controlsPanel.setBorder(createTitledBorder("Controls"));

        // Thêm trực tiếp các checkbox vào panel.
        controlsPanel.add(highlightCheckBox);
        controlsPanel.add(noteCheckBox);
        controlsPanel.add(autoBypassCheckBox);

        // Checkbox sửa history + ô nhập ngưỡng hàng chờ nằm cùng một dòng.
        JPanel autoAnnotatePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        autoAnnotatePanel.add(autoAnnotateHistoryCheckBox);
        autoAnnotatePanel.add(new JLabel("  queue threshold: "));
        autoAnnotatePanel.add(annotationBatchField);
        autoAnnotatePanel.add(new JLabel(" APIs"));
        autoAnnotatePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        autoAnnotatePanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, autoAnnotatePanel.getPreferredSize().height));
        controlsPanel.add(autoAnnotatePanel);
        
        centerPanel.add(controlsPanel);

        /* ========= PANEL PHÍA ĐÔNG (EAST) - Chứa thống kê ========= */
        JPanel eastPanel = new JPanel(new BorderLayout());
        
        JPanel statsPanel = new JPanel();
        statsPanel.setBorder(createTitledBorder("Statistics"));
        // GridLayout để các label thống kê được xếp đều nhau.
        statsPanel.setLayout(new GridLayout(5, 1, 0, 10));
        statsPanel.setPreferredSize(new Dimension(220, 200));

        // Thiết lập font và border cho các label thống kê.
        Font statFont = totalLbl.getFont().deriveFont(Font.PLAIN, 15f);
        for (JLabel lbl : new JLabel[]{totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl}) {
            lbl.setFont(statFont);
            lbl.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
            statsPanel.add(lbl);
        }
        
        eastPanel.add(statsPanel, BorderLayout.NORTH);


        /* ========= PANEL PHÍA NAM (SOUTH) - Chứa nút Apply ========= */
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        applyButton.setPreferredSize(new Dimension(150, 32));
        applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD, 13f));
        southPanel.add(applyButton);
        
        /* ========= LẮP RÁP CÁC PANEL VÀO PANEL GỐC ========= */
        settingsPanel.add(centerPanel, BorderLayout.CENTER);
        settingsPanel.add(eastPanel, BorderLayout.EAST);
        settingsPanel.add(southPanel, BorderLayout.SOUTH);

        return settingsPanel;
    }

    /**
     * Phương thức tiện ích để tạo một đường viền có tiêu đề (TitledBorder).
     * @param title Tiêu đề của đường viền.
     * @return một đối tượng Border đã được định dạng.
     */
    private static Border createTitledBorder(String title) {
        TitledBorder border = BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), title
        );
        border.setTitleFont(border.getTitleFont().deriveFont(Font.BOLD, 13f));
        return BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(5, 0, 5, 0),
                border
        );
    }
}
