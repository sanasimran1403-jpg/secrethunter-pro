package com.sanasimran.secrethunter.ui;

import com.sanasimran.secrethunter.model.CweMapper;
import com.sanasimran.secrethunter.model.SecretMatch;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class FindingsTableModel extends AbstractTableModel {

    private final String[] columns = {"#", "Severity", "Type", "Value", "Method", "CWE", "URL"};
    private final List<Object[]> rows = new ArrayList<>();

    public synchronized void addFinding(String url, SecretMatch match) {
        int id = rows.size() + 1;
        rows.add(new Object[]{
                id,
                match.getSeverity(),
                match.getType(),
                match.getMaskedValue(),
                match.getDetectionMethod(),
                CweMapper.getCwe(match.getType()),
                url
        });
        int rowIndex = rows.size() - 1;
        fireTableRowsInserted(rowIndex, rowIndex);
    }

    public synchronized void clearFindings() {
        int size = rows.size();
        rows.clear();
        if (size > 0) {
            fireTableRowsDeleted(0, size - 1);
        }
    }

    public synchronized void removeRow(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) return;
        rows.remove(modelRow);
        // renumber remaining rows
        for (int i = 0; i < rows.size(); i++) {
            rows.get(i)[0] = i + 1;
        }
        fireTableDataChanged();
    }

    public synchronized String getFullValueAt(int rowIndex) {
        return (String) rows.get(rowIndex)[3];
    }

    public synchronized String getUrlAt(int rowIndex) {
        return (String) rows.get(rowIndex)[6];
    }

    public synchronized List<Object[]> getAllRows() {
        return new ArrayList<>(rows);
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public String getColumnName(int col) {
        return columns[col];
    }

    @Override
    public synchronized Object getValueAt(int rowIndex, int columnIndex) {
        return rows.get(rowIndex)[columnIndex];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0) return Integer.class;
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }
}