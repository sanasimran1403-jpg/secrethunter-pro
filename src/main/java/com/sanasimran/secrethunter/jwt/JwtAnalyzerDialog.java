package com.sanasimran.secrethunter.jwt;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class JwtAnalyzerDialog {

    public static void show(String rawToken) {
        JwtParser.DecodedJwt decoded = JwtParser.decode(rawToken);

        JFrame frame = new JFrame("SecretHunter Pro - JWT Analyzer");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setSize(750, 600);
        frame.setLayout(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();

        // --- Decoded tab ---
        JTextArea decodedArea = new JTextArea();
        decodedArea.setEditable(false);
        decodedArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        if (decoded != null) {
            decodedArea.setText(
                    "HEADER:\n" + prettyPrint(decoded.header) +
                    "\n\nPAYLOAD:\n" + prettyPrint(decoded.payload) +
                    "\n\nSIGNATURE:\n" + decoded.signature
            );
        } else {
            decodedArea.setText("Failed to decode token. Make sure it's a valid JWT (header.payload.signature).");
        }
        tabs.addTab("Decoded", new JScrollPane(decodedArea));

        // --- Attack results tab ---
        JTextArea attackArea = new JTextArea();
        attackArea.setEditable(false);
        attackArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane attackScroll = new JScrollPane(attackArea);

        JButton runAttackButton = new JButton("Run Attacks (alg=none + weak secret brute-force)");
        runAttackButton.addActionListener(e -> {
            attackArea.setText("Running attacks...\n");
            new SwingWorker<Void, Void>() {
                StringBuilder result = new StringBuilder();

                @Override
                protected Void doInBackground() {
                    result.append("=== alg=none Attack Variants ===\n");
                    result.append("(Send these as the Authorization header / token value to test if the server accepts unsigned tokens)\n\n");
                    if (decoded != null) {
                        List<String> variants = JwtAttacker.generateAlgNoneTokens(decoded.payload);
                        int i = 1;
                        for (String variant : variants) {
                            result.append("Variant ").append(i++).append(":\n").append(variant).append("\n\n");
                        }
                    }

                    result.append("\n=== Weak Secret Brute-Force (HMAC-SHA256) ===\n");
                    if (rawToken.split("\\.").length == 3 && decoded != null) {
                        String[] parts = rawToken.split("\\.");
                        String signingInput = parts[0] + "." + parts[1];
                        List<String> wordlist = WordlistLoader.loadDefaultWordlist();
                        result.append("Testing ").append(wordlist.size()).append(" common secrets...\n");

                        String found = JwtAttacker.bruteForceSecret(parts[0], parts[1], parts[2], wordlist);
                        if (found != null) {
                            result.append("\n*** WEAK SECRET FOUND: \"").append(found).append("\" ***\n");
                            result.append("This token can be forged! Use this secret to sign arbitrary tokens.\n");
                        } else {
                            result.append("\nNo match found in default wordlist (").append(wordlist.size()).append(" entries).\n");
                            result.append("Token may use a strong secret, or algorithm may not be HMAC-SHA256.\n");
                        }
                    } else {
                        result.append("Skipped - token missing signature part.\n");
                    }
                    return null;
                }

                @Override
                protected void done() {
                    attackArea.setText(result.toString());
                }
            }.execute();
        });

        JPanel attackPanel = new JPanel(new BorderLayout());
        attackPanel.add(runAttackButton, BorderLayout.NORTH);
        attackPanel.add(attackScroll, BorderLayout.CENTER);
        tabs.addTab("Attacks", attackPanel);

        frame.add(tabs, BorderLayout.CENTER);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static String prettyPrint(String json) {
        // simple indentation for readability, not a full JSON formatter
        StringBuilder sb = new StringBuilder();
        int indent = 0;
        boolean inQuotes = false;
        for (char c : json.toCharArray()) {
            if (c == '"') inQuotes = !inQuotes;
            if (!inQuotes) {
                if (c == '{' || c == '[') {
                    sb.append(c).append("\n");
                    indent++;
                    sb.append("  ".repeat(indent));
                    continue;
                } else if (c == '}' || c == ']') {
                    sb.append("\n");
                    indent--;
                    sb.append("  ".repeat(Math.max(indent, 0)));
                    sb.append(c);
                    continue;
                } else if (c == ',') {
                    sb.append(c).append("\n").append("  ".repeat(indent));
                    continue;
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }
}