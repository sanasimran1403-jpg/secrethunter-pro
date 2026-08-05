package com.sanasimran.secrethunter.ui;

import com.sanasimran.secrethunter.config.CustomPatternStore;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class SettingsPanel {

    private final JPanel mainPanel;
    private final DefaultTableModel tableModel;
    private final JTable table;

    public SettingsPanel() {
        mainPanel = new JPanel(new BorderLayout());

        JLabel infoLabel = new JLabel("Add custom regex patterns to detect project-specific secrets or sensitive data.");
        infoLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        tableModel = new DefaultTableModel(new String[]{"Name", "Regex Pattern", "Severity"}, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };
        table = new JTable(tableModel);
        table.setRowHeight(24);
        JScrollPane scrollPane = new JScrollPane(table);

        JButton addButton = new JButton("Add Custom Pattern");
        addButton.addActionListener(e -> showAddDialog());

        JButton removeButton = new JButton("Remove Selected");
        removeButton.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                CustomPatternStore.removePattern(row);
                refreshTable();
            } else {
                JOptionPane.showMessageDialog(mainPanel, "Select a pattern to remove.", "No Selection", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(infoLabel, BorderLayout.NORTH);
        topPanel.add(buttonPanel, BorderLayout.SOUTH);

        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        refreshTable();
    }

    private void showAddDialog() {
        JTextField nameField = new JTextField();
        JTextField regexField = new JTextField();
        JComboBox<String> severityBox = new JComboBox<>(new String[]{"High", "Medium", "Low"});

        JPanel panel = new JPanel(new GridLayout(0, 1, 5, 5));
        panel.add(new JLabel("Pattern Name (e.g. \"Internal Token\"):"));
        panel.add(nameField);
        panel.add(new JLabel("Regex Pattern (Java regex syntax):"));
        panel.add(regexField);
        panel.add(new JLabel("Severity:"));
        panel.add(severityBox);

        int result = JOptionPane.showConfirmDialog(mainPanel, panel, "Add Custom Pattern",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            String name = nameField.getText().trim();
            String regex = regexField.getText().trim();
            String severity = (String) severityBox.getSelectedItem();

            if (name.isEmpty() || regex.isEmpty()) {
                JOptionPane.showMessageDialog(mainPanel, "Name and regex pattern cannot be empty.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                Pattern.compile(regex);
            } catch (PatternSyntaxException ex) {
                JOptionPane.showMessageDialog(mainPanel,
                        "Invalid regex syntax:\n" + ex.getMessage(),
                        "Invalid Pattern", JOptionPane.ERROR_MESSAGE);
                return;
            }

            CustomPatternStore.addPattern(name, regex, severity);
            refreshTable();
        }
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (CustomPatternStore.CustomPattern cp : CustomPatternStore.getAll()) {
            tableModel.addRow(new Object[]{cp.name, cp.regex, cp.severity});
        }
    }

    public Component getUiComponent() {
        return mainPanel;
    }
}