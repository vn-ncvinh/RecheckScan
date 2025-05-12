package com.example;

import javax.swing.*;
import java.awt.*;

public class SettingsPanel {
    public static JPanel create(JTextArea extensionArea, JTextField outputPathField, JButton browseButton, JButton applyButton) {
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Extension area
        JScrollPane extScroll = new JScrollPane(extensionArea);
        extScroll.setBorder(BorderFactory.createTitledBorder("Excluded Extensions (comma-separated)"));
        extensionArea.setRows(2);

        // Output path
        JPanel outputPathPanel = new JPanel(new FlowLayout(FlowLayout.LEADING, 5, 5));
        outputPathPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        outputPathField.setPreferredSize(new Dimension(200, 24));
        outputPathPanel.add(new JLabel("Log Output Path: "));
        outputPathPanel.add(outputPathField);
        outputPathPanel.add(browseButton);

        // Apply button panel
        applyButton.setPreferredSize(new Dimension(100, 32));
        applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD, 13f));
        JPanel applyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        applyPanel.add(applyButton);

        // Add to main panel
        settingsPanel.add(extScroll);
        settingsPanel.add(Box.createRigidArea(new Dimension(0, 8)));
        settingsPanel.add(outputPathPanel);
        settingsPanel.add(Box.createRigidArea(new Dimension(0, 8)));
        settingsPanel.add(applyPanel);

        return settingsPanel;
    }
}
