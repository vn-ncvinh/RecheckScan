package com.example;

import javax.swing.*;
import java.awt.*;

class SettingsPanel {
    public static JPanel create(JTextArea extensionArea, JTextField outputPathField, JButton browseButton, JButton highlightButton, JButton noteButton, JButton applyButton) {
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

        // Toggle Buttons side-by-side
        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        highlightButton.setPreferredSize(new Dimension(140, 32));
        noteButton.setPreferredSize(new Dimension(140, 32));
        highlightButton.setFont(highlightButton.getFont().deriveFont(Font.BOLD, 13f));
        noteButton.setFont(noteButton.getFont().deriveFont(Font.BOLD, 13f));
        togglePanel.add(highlightButton);
        togglePanel.add(noteButton);

        // Apply panel
        applyButton.setPreferredSize(new Dimension(150, 32));
        applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD, 13f));
        JPanel applyPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        applyPanel.add(applyButton);

        // Add components
        settingsPanel.add(extScroll);
        settingsPanel.add(Box.createRigidArea(new Dimension(0, 8)));
        settingsPanel.add(outputPathPanel);
        settingsPanel.add(Box.createRigidArea(new Dimension(0, 8)));
        settingsPanel.add(togglePanel);
        settingsPanel.add(applyPanel);

        return settingsPanel;
    }
}
