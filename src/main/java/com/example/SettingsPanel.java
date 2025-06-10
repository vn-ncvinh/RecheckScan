package com.example;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class SettingsPanel {

    public static JPanel create(
            JTextArea  extensionArea,
            JTextField outputPathField,
            JButton    browseButton,
            JCheckBox  highlightCheckBox, // FIXED: Changed from JButton
            JCheckBox  noteCheckBox,      // FIXED: Changed from JButton
            JCheckBox  autoBypassCheckBox,
            JButton    applyButton,
            JLabel     totalLbl,
            JLabel     scannedLbl,
            JLabel     rejectedLbl,
            JLabel     bypassLbl,
            JLabel     unverifiedLbl) {

        /* ========= ROOT PANEL ========= */
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BorderLayout(10, 10));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        /* ========= CENTER PANEL (MAIN CONTROLS) ========= */
        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));

        // --- Project Settings Group ---
        JPanel projectSettingsPanel = new JPanel();
        projectSettingsPanel.setLayout(new BoxLayout(projectSettingsPanel, BoxLayout.Y_AXIS));
        projectSettingsPanel.setBorder(createTitledBorder("Project Settings"));
        
        JPanel outputPathPanel = new JPanel(new BorderLayout(5,0));
        outputPathPanel.add(new JLabel("Log Output Path: "), BorderLayout.WEST);
        outputPathPanel.add(outputPathField, BorderLayout.CENTER);
        outputPathPanel.add(browseButton, BorderLayout.EAST);
        outputPathPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, outputPathField.getPreferredSize().height));
        outputPathPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        projectSettingsPanel.add(outputPathPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        extensionArea.setRows(1);
        JScrollPane extScroll = new JScrollPane(extensionArea);
        extScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, extScroll.getPreferredSize().height + 10));
        extScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        projectSettingsPanel.add(extScroll);
        
        centerPanel.add(projectSettingsPanel);
        centerPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // --- Controls Group ---
        JPanel controlsPanel = new JPanel();
        controlsPanel.setLayout(new BoxLayout(controlsPanel, BoxLayout.Y_AXIS));
        controlsPanel.setBorder(createTitledBorder("Controls"));

        // FIXED: Add checkboxes directly to the panel
        controlsPanel.add(highlightCheckBox);
        controlsPanel.add(noteCheckBox);
        controlsPanel.add(autoBypassCheckBox);
        
        centerPanel.add(controlsPanel);

        /* ========= EAST PANEL (STATISTICS) ========= */
        JPanel eastPanel = new JPanel(new BorderLayout());
        
        JPanel statsPanel = new JPanel();
        statsPanel.setBorder(createTitledBorder("Statistics"));
        statsPanel.setLayout(new GridLayout(5, 1, 0, 10));
        statsPanel.setPreferredSize(new Dimension(220, 200));

        Font statFont = totalLbl.getFont().deriveFont(Font.PLAIN, 15f);
        for (JLabel lbl : new JLabel[]{totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl}) {
            lbl.setFont(statFont);
            lbl.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
            statsPanel.add(lbl);
        }
        
        eastPanel.add(statsPanel, BorderLayout.NORTH);


        /* ========= SOUTH PANEL (APPLY BUTTON) ========= */
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        applyButton.setPreferredSize(new Dimension(150, 32));
        applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD, 13f));
        southPanel.add(applyButton);
        
        /* ========= ASSEMBLE PANELS ========= */
        settingsPanel.add(centerPanel, BorderLayout.CENTER);
        settingsPanel.add(eastPanel, BorderLayout.EAST);
        settingsPanel.add(southPanel, BorderLayout.SOUTH);

        return settingsPanel;
    }

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