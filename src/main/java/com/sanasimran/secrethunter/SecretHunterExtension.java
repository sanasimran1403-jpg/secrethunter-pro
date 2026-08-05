package com.sanasimran.secrethunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.sanasimran.secrethunter.scanner.PassiveSecretScanner;
import com.sanasimran.secrethunter.ui.SecretHunterContextMenu;
import com.sanasimran.secrethunter.ui.SecretHunterTab;

public class SecretHunterExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("SecretHunter Pro");
        api.logging().logToOutput("[+] SecretHunter Pro loaded successfully!");
        api.logging().logToOutput("[+] Author: Sana Simran");
        api.logging().logToOutput("[+] Passive detection engine active...");

        SecretHunterTab tab = new SecretHunterTab();
        api.userInterface().registerSuiteTab("SecretHunter Pro", tab.getUiComponent());

        api.http().registerHttpHandler(new PassiveSecretScanner(api, tab));

        api.userInterface().registerContextMenuItemsProvider(new SecretHunterContextMenu(api));

        api.logging().logToOutput("[+] Custom UI tab registered.");
        api.logging().logToOutput("[+] JWT Analyzer context menu registered.");
        api.logging().logToOutput("[+] IDOR/SSRF parameter analysis active (built-in, Community Edition compatible).");
    }
}