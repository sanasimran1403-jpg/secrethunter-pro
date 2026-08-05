package com.sanasimran.secrethunter.jwt;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class WordlistLoader {

    public static List<String> loadDefaultWordlist() {
        List<String> words = new ArrayList<>();
        try (InputStream is = WordlistLoader.class.getResourceAsStream("/wordlists/jwt-secrets.txt")) {
            if (is == null) return words;
            BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) words.add(line);
            }
        } catch (Exception e) {
            // silently return whatever was loaded
        }
        return words;
    }
}