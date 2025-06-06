package com.example;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class SettingsPanel {

    public static JPanel create(
            JTextArea  extensionArea,
            JTextField outputPathField,
            JButton    browseButton,
            JButton    highlightButton,
            JButton    noteButton,
            JButton    applyButton,
            JLabel     totalLbl,
            JLabel     scannedLbl,
            JLabel     rejectedLbl,
            JLabel     bypassLbl) {

        /* ========= ROOT ========= */
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        /* ========= “Excluded Extensions” ========= */
        extensionArea.setRows(2);
        JScrollPane extScroll = new JScrollPane(extensionArea);
        extScroll.setBorder(
                BorderFactory.createTitledBorder("Excluded Extensions (comma-separated)"));

        /* ========= Log output path ========= */
        JPanel outputPathPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 5, 5));
        outputPathField.setPreferredSize(new Dimension(200, 24));
        outputPathPanel.add(new JLabel("Log Output Path: "));
        outputPathPanel.add(outputPathField);
        outputPathPanel.add(browseButton);

        /* ========= Toggle buttons (trái) ========= */
        Dimension btnSize = new Dimension(140, 32);
        for (JButton b : new JButton[]{highlightButton, noteButton}) {
            b.setPreferredSize(btnSize);
            b.setMinimumSize(btnSize);
            b.setMaximumSize(btnSize);                 // khoá width
            b.setFont(b.getFont().deriveFont(Font.BOLD, 13f));
        }
        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        togglePanel.add(highlightButton);
        togglePanel.add(noteButton);


        JPanel statsPanel = new JPanel();

        TitledBorder statsBorder = BorderFactory.createTitledBorder("Statistics");
        Font baseFont = statsBorder.getTitleFont();                   // font mặc định
        if (baseFont == null) baseFont = statsPanel.getFont();        // fallback
        statsBorder.setTitleFont(baseFont.deriveFont(Font.BOLD));     // in đậm
        statsPanel.setBorder(statsBorder);
        statsPanel.setLayout(new GridLayout(4, 1, 0, 6)); // 4 hàng – 1 cột, cách dòng 6 px

        Font statFont = totalLbl.getFont().deriveFont(Font.PLAIN, 15f);
        for (JLabel lbl : new JLabel[]{totalLbl, scannedLbl, rejectedLbl, bypassLbl}) {
            lbl.setFont(statFont);
            lbl.setHorizontalAlignment(SwingConstants.LEFT); // bám lề trái
            statsPanel.add(lbl);                             // add theo thứ tự → thẳng hàng
        }
        // kích thước cố định để không tràn full màn hình
        int statsW = 300, statsH = 150;
        statsPanel.setPreferredSize(new Dimension(statsW, statsH));
        statsPanel.setMinimumSize  (new Dimension(statsW, statsH));
        statsPanel.setMaximumSize  (new Dimension(statsW, statsH));

        /* ========= Middle panel =========
           | Toggle |  (glue)  |  Statistics | (glue) |
           => Statistics nằm giữa
        */
        JPanel middlePanel = new JPanel();
        middlePanel.setLayout(new BoxLayout(middlePanel, BoxLayout.X_AXIS));
        middlePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        middlePanel.add(togglePanel);
        middlePanel.add(Box.createHorizontalGlue());   // lò xo trái
        middlePanel.add(statsPanel);
        middlePanel.add(Box.createHorizontalGlue());   // lò xo phải

        /* ========= Apply button ========= */
        applyButton.setPreferredSize(new Dimension(150, 32));
        applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD, 13f));
        JPanel applyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        applyPanel.add(applyButton);

        /* ========= Assemble ========= */
        settingsPanel.add(extScroll);
        settingsPanel.add(Box.createRigidArea(new Dimension(0, 8)));
        settingsPanel.add(outputPathPanel);
        settingsPanel.add(Box.createRigidArea(new Dimension(0, 8)));
        settingsPanel.add(middlePanel);
        settingsPanel.add(Box.createRigidArea(new Dimension(0, 8)));
        settingsPanel.add(applyPanel);

        return settingsPanel;
    }
}
