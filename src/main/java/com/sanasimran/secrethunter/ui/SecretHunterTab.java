package com.sanasimran.secrethunter.ui;

import com.sanasimran.secrethunter.report.ReportExporter;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;

public class SecretHunterTab {

    private final JPanel mainPanel;
    private final JPanel findingsPanel;
    private final FindingsTableModel tableModel;
    private final JTable table;
    private final JLabel statusLabel;

    public SecretHunterTab() {
        findingsPanel = new JPanel(new BorderLayout());

        tableModel = new FindingsTableModel();
        table = new JTable(tableModel);

        table.setRowHeight(24);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        table.getColumnModel().getColumn(0).setPreferredWidth(30);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(2).setPreferredWidth(150);
        table.getColumnModel().getColumn(3).setPreferredWidth(150);
        table.getColumnModel().getColumn(4).setPreferredWidth(110);
        table.getColumnModel().getColumn(5).setPreferredWidth(220);
        table.getColumnModel().getColumn(6).setPreferredWidth(250);

        table.setDefaultRenderer(Object.class, new SeverityRowRenderer());

        TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0) {
                        table.setRowSelectionInterval(row, row);
                        showContextMenu(e, row);
                    }
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(table);

        statusLabel = new JLabel("Findings: 0");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        JButton clearButton = new JButton("Clear Findings");
        clearButton.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(findingsPanel,
                    "Clear all findings? This cannot be undone.", "Confirm",
                    JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                tableModel.clearFindings();
                updateStatus();
            }
        });

        JButton exportJsonBtn = new JButton("Export JSON");
        exportJsonBtn.addActionListener(e -> exportFindings("json"));

        JButton exportCsvBtn = new JButton("Export CSV");
        exportCsvBtn.addActionListener(e -> exportFindings("csv"));

        JButton exportHtmlBtn = new JButton("Export HTML");
        exportHtmlBtn.addActionListener(e -> exportFindings("html"));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        buttonPanel.add(exportJsonBtn);
        buttonPanel.add(exportCsvBtn);
        buttonPanel.add(exportHtmlBtn);
        buttonPanel.add(clearButton);

        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(statusLabel, BorderLayout.WEST);
        topPanel.add(buttonPanel, BorderLayout.EAST);

        findingsPanel.add(topPanel, BorderLayout.NORTH);
        findingsPanel.add(scrollPane, BorderLayout.CENTER);

        // Combine Findings + Settings into tabs
        SettingsPanel settingsPanel = new SettingsPanel();
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Findings", findingsPanel);
        tabbedPane.addTab("Settings", settingsPanel.getUiComponent());

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    private void exportFindings(String format) {
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(findingsPanel, "No findings to export.", "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("secrethunter-report." + format));
        int result = chooser.showSaveDialog(findingsPanel);

        if (result == JFileChooser.APPROVE_OPTION) {
            String path = chooser.getSelectedFile().getAbsolutePath();
            if (!path.toLowerCase().endsWith("." + format)) {
                path += "." + format;
            }
            try {
                switch (format) {
                    case "json" -> ReportExporter.exportJson(tableModel.getAllRows(), path);
                    case "csv" -> ReportExporter.exportCsv(tableModel.getAllRows(), path);
                    case "html" -> ReportExporter.exportHtml(tableModel.getAllRows(), path);
                }
                JOptionPane.showMessageDialog(findingsPanel, "Report exported to:\n" + path, "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(findingsPanel, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void showContextMenu(MouseEvent e, int row) {
        JPopupMenu menu = new JPopupMenu();

        JMenuItem copyItem = new JMenuItem("Copy value");
        copyItem.addActionListener(a -> {
            int modelRow = table.convertRowIndexToModel(row);
            String value = tableModel.getFullValueAt(modelRow);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(value), null);
        });

        JMenuItem copyUrlItem = new JMenuItem("Copy URL");
        copyUrlItem.addActionListener(a -> {
            int modelRow = table.convertRowIndexToModel(row);
            String url = tableModel.getUrlAt(modelRow);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url), null);
        });

        JMenuItem removeItem = new JMenuItem("Mark as False Positive (remove)");
        removeItem.addActionListener(a -> {
            int modelRow = table.convertRowIndexToModel(row);
            tableModel.removeRow(modelRow);
            updateStatus();
        });

        menu.add(copyItem);
        menu.add(copyUrlItem);
        menu.addSeparator();
        menu.add(removeItem);
        menu.show(e.getComponent(), e.getX(), e.getY());
    }

    public void addFinding(String url, com.sanasimran.secrethunter.model.SecretMatch match) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addFinding(url, match);
            updateStatus();
        });
    }

    private void updateStatus() {
        statusLabel.setText("Findings: " + tableModel.getRowCount());
    }

    public Component getUiComponent() {
        return mainPanel;
    }

    private static class SeverityRowRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                         boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected) {
                int modelRow = table.convertRowIndexToModel(row);
                Object severity = table.getModel().getValueAt(modelRow, 1);
                if ("High".equals(severity)) {
                    c.setBackground(new Color(255, 205, 210));
                } else if ("Medium".equals(severity)) {
                    c.setBackground(new Color(255, 236, 179));
                } else {
                    c.setBackground(new Color(220, 237, 200));
                }
            } else {
                c.setBackground(table.getSelectionBackground());
            }
            return c;
        }
    }
}