package com.sanasimran.secrethunter.report;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;

public class ReportExporter {

    public static void exportJson(List<Object[]> rows, String filePath) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"tool\": \"SecretHunter Pro\",\n");
        sb.append("  \"generated\": \"").append(timestamp()).append("\",\n");
        sb.append("  \"totalFindings\": ").append(rows.size()).append(",\n");
        sb.append("  \"findings\": [\n");

        for (int i = 0; i < rows.size(); i++) {
            Object[] row = rows.get(i);
            sb.append("    {\n");
            sb.append("      \"id\": ").append(row[0]).append(",\n");
            sb.append("      \"severity\": \"").append(escape(row[1])).append("\",\n");
            sb.append("      \"type\": \"").append(escape(row[2])).append("\",\n");
            sb.append("      \"value\": \"").append(escape(row[3])).append("\",\n");
            sb.append("      \"method\": \"").append(escape(row[4])).append("\",\n");
            sb.append("      \"cwe\": \"").append(escape(row[5])).append("\",\n");
            sb.append("      \"url\": \"").append(escape(row[6])).append("\"\n");
            sb.append("    }").append(i < rows.size() - 1 ? "," : "").append("\n");
        }

        sb.append("  ]\n");
        sb.append("}\n");

        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(sb.toString());
        }
    }

    public static void exportCsv(List<Object[]> rows, String filePath) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("ID,Severity,Type,Value,Method,CWE,URL\n");

        for (Object[] row : rows) {
            sb.append(row[0]).append(",");
            sb.append(csvEscape(row[1])).append(",");
            sb.append(csvEscape(row[2])).append(",");
            sb.append(csvEscape(row[3])).append(",");
            sb.append(csvEscape(row[4])).append(",");
            sb.append(csvEscape(row[5])).append(",");
            sb.append(csvEscape(row[6])).append("\n");
        }

        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(sb.toString());
        }
    }

    public static void exportHtml(List<Object[]> rows, String filePath) throws IOException {
        int high = 0, medium = 0, low = 0;
        for (Object[] row : rows) {
            String sev = String.valueOf(row[1]);
            if ("High".equals(sev)) high++;
            else if ("Medium".equals(sev)) medium++;
            else low++;
        }

        int riskScore = Math.min(100, (high * 25) + (medium * 10) + (low * 3));
        String riskLevel = riskScore >= 75 ? "CRITICAL" : riskScore >= 50 ? "HIGH" : riskScore >= 25 ? "MEDIUM" : "LOW";
        String statusLabel = rows.isEmpty() ? "CLEAN" : "VULNERABLE";
        String statusColor = rows.isEmpty() ? "#2ecc71" : "#ff4d4d";

        String logoBase64 = loadLogoBase64();

        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"UTF-8\">\n<title>SecretHunter Pro - Findings Report</title>\n");
        sb.append("<style>\n");
        sb.append("* { box-sizing: border-box; }\n");
        sb.append("body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 40px; background: #0d1524; color: #e8ecf3; }\n");
        sb.append(".container { max-width: 1000px; margin: 0 auto; }\n");

        sb.append(".header { background: #131c30; border: 1px solid #22304a; border-radius: 8px; padding: 24px 30px; margin-bottom: 8px; display: flex; align-items: center; justify-content: center; gap: 16px; }\n");
        sb.append(".header img { height: 48px; }\n");
        sb.append(".header h1 { font-size: 26px; margin: 0; color: #ffffff; letter-spacing: 0.5px; }\n");
        sb.append(".subtitle { text-align: center; color: #8b98b0; font-size: 13px; margin: 10px 0 28px 0; }\n");

        sb.append(".status-box { border: 1px solid ").append(statusColor).append("; background: #151c2e; border-radius: 8px; padding: 26px; text-align: center; margin-bottom: 32px; }\n");
        sb.append(".status-box .status { font-size: 34px; font-weight: 800; color: ").append(statusColor).append("; letter-spacing: 2px; margin-bottom: 10px; }\n");
        sb.append(".status-box .meta { color: #b7c1d6; font-size: 13px; }\n");
        sb.append(".status-box .meta b { color: #ffffff; }\n");

        sb.append(".section-title { display: flex; align-items: center; gap: 8px; font-size: 17px; font-weight: 700; color: #ffffff; margin: 30px 0 12px 0; }\n");
        sb.append(".section-title .sq { width: 10px; height: 10px; background: #4a7dff; display: inline-block; }\n");
        sb.append("hr { border: none; border-top: 1px solid #22304a; margin-bottom: 14px; }\n");

        sb.append("table { border-collapse: collapse; width: 100%; margin-bottom: 10px; }\n");
        sb.append("th { background: #182338; color: #9fb0cc; text-align: left; padding: 10px 12px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #22304a; }\n");
        sb.append("td { padding: 10px 12px; border-bottom: 1px solid #1c2740; font-size: 13px; color: #d7deec; vertical-align: top; }\n");
        sb.append("tr:hover td { background: #131d33; }\n");

        sb.append(".badge { padding: 3px 10px; border-radius: 4px; font-weight: 700; font-size: 11px; display: inline-block; }\n");
        sb.append(".badge-High { background: rgba(255,77,77,0.15); color: #ff6b6b; border: 1px solid #ff4d4d; }\n");
        sb.append(".badge-Medium { background: rgba(255,176,32,0.15); color: #ffb020; border: 1px solid #ffb020; }\n");
        sb.append(".badge-Low { background: rgba(46,204,113,0.15); color: #4ade80; border: 1px solid #2ecc71; }\n");

        sb.append("code { background: #1a2438; padding: 2px 6px; border-radius: 3px; color: #7dd3fc; font-size: 12px; }\n");

        sb.append(".footer { display: flex; justify-content: space-between; color: #6b7891; font-size: 12px; border-top: 1px solid #22304a; padding-top: 14px; margin-top: 30px; }\n");
        sb.append("</style>\n</head>\n<body>\n<div class=\"container\">\n");

        sb.append("<div class=\"header\">\n");
        if (logoBase64 != null) {
            sb.append("<img src=\"data:image/png;base64,").append(logoBase64).append("\" alt=\"S&S Logo\">\n");
        }
        sb.append("<h1>SecretHunter Pro &mdash; Findings Report</h1>\n");
        sb.append("</div>\n");

        sb.append("<div class=\"subtitle\">Generated: ").append(timestamp()).append(" | S&amp;S Cybersecurity</div>\n");

        sb.append("<div class=\"status-box\">\n");
        sb.append("<div class=\"status\">").append(statusLabel).append("</div>\n");
        sb.append("<div class=\"meta\">Risk Score: <b>").append(riskScore).append("/100</b> &nbsp;|&nbsp; Risk Level: <b>")
          .append(riskLevel).append("</b> &nbsp;|&nbsp; Total Findings: <b>").append(rows.size()).append("</b></div>\n");
        sb.append("</div>\n");

        sb.append("<div class=\"section-title\"><span class=\"sq\"></span> Scan Summary</div><hr>\n");
        sb.append("<table>\n<tr><th>Metric</th><th>Value</th></tr>\n");
        sb.append("<tr><td>Total Findings</td><td>").append(rows.size()).append("</td></tr>\n");
        sb.append("<tr><td>High Severity</td><td>").append(high).append("</td></tr>\n");
        sb.append("<tr><td>Medium Severity</td><td>").append(medium).append("</td></tr>\n");
        sb.append("<tr><td>Low Severity</td><td>").append(low).append("</td></tr>\n");
        sb.append("</table>\n");

        sb.append("<div class=\"section-title\"><span class=\"sq\"></span> Detailed Findings (").append(rows.size()).append(" found)</div><hr>\n");

        if (rows.isEmpty()) {
            sb.append("<p style=\"color:#8b98b0;\">No findings detected.</p>\n");
        } else {
            sb.append("<table>\n<tr><th>#</th><th>Severity</th><th>Type</th><th>Value</th><th>Method</th><th>CWE</th><th>URL</th></tr>\n");
            for (Object[] row : rows) {
                String severity = String.valueOf(row[1]);
                sb.append("<tr>\n");
                sb.append("<td>").append(row[0]).append("</td>\n");
                sb.append("<td><span class=\"badge badge-").append(severity).append("\">").append(severity).append("</span></td>\n");
                sb.append("<td>").append(htmlEscape(row[2])).append("</td>\n");
                sb.append("<td><code>").append(htmlEscape(row[3])).append("</code></td>\n");
                sb.append("<td>").append(htmlEscape(row[4])).append("</td>\n");
                sb.append("<td>").append(htmlEscape(row[5])).append("</td>\n");
                sb.append("<td style=\"word-break: break-all;\">").append(htmlEscape(row[6])).append("</td>\n");
                sb.append("</tr>\n");
            }
            sb.append("</table>\n");
        }

        sb.append("<div class=\"footer\">\n");
        sb.append("<span>S&amp;S | SecretHunter Pro</span>\n");
        sb.append("<span>Confidential &mdash; For Authorized Use Only</span>\n");
        sb.append("</div>\n");

        sb.append("</div>\n</body>\n</html>\n");

        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(sb.toString());
        }
    }

    private static String loadLogoBase64() {
        try (InputStream is = ReportExporter.class.getResourceAsStream("/images/sns-logo.png")) {
            if (is == null) return null;
            byte[] bytes = is.readAllBytes();
            return Base64.getEncoder().encodeToString(bytes);
        } catch (Exception e) {
            return null;
        }
    }

    private static String timestamp() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + " UTC";
    }

    private static String escape(Object value) {
        return String.valueOf(value).replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String csvEscape(Object value) {
        String str = String.valueOf(value);
        if (str.contains(",") || str.contains("\"") || str.contains("\n")) {
            str = "\"" + str.replace("\"", "\"\"") + "\"";
        }
        return str;
    }

    private static String htmlEscape(Object value) {
        return String.valueOf(value)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}