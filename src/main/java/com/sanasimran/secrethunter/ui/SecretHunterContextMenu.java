package com.sanasimran.secrethunter.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import com.sanasimran.secrethunter.jwt.JwtAnalyzerDialog;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecretHunterContextMenu implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private static final Pattern JWT_PATTERN =
            Pattern.compile("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");

    public SecretHunterContextMenu(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        String content = extractContent(event);
        if (content == null || content.isBlank()) {
            return items;
        }

        Matcher matcher = JWT_PATTERN.matcher(content);
        if (matcher.find()) {
            String token = matcher.group();
            JMenuItem jwtItem = new JMenuItem("Send to SecretHunter JWT Analyzer");
            jwtItem.addActionListener(e -> JwtAnalyzerDialog.show(token));
            items.add(jwtItem);
        }

        return items;
    }

    private String extractContent(ContextMenuEvent event) {
        // Case 1: right-click inside a request/response editor (Proxy, Repeater, etc.)
        Optional<MessageEditorHttpRequestResponse> editorContext = event.messageEditorRequestResponse();
        if (editorContext.isPresent()) {
            HttpRequestResponse rr = editorContext.get().requestResponse();
            StringBuilder sb = new StringBuilder();
            if (rr.request() != null) sb.append(rr.request().toString());
            if (rr.response() != null) sb.append(rr.response().toString());
            return sb.toString();
        }

        // Case 2: right-click on a list of requests (e.g. Proxy HTTP history)
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (HttpRequestResponse rr : selected) {
                if (rr.request() != null) sb.append(rr.request().toString());
                if (rr.response() != null) sb.append(rr.response().toString());
            }
            return sb.toString();
        }

        return null;
    }
}