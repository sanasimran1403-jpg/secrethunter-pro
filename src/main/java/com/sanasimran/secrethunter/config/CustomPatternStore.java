package com.sanasimran.secrethunter.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CustomPatternStore {

    public static class CustomPattern {
        public final String name;
        public final String regex;
        public final String severity;

        public CustomPattern(String name, String regex, String severity) {
            this.name = name;
            this.regex = regex;
            this.severity = severity;
        }
    }

    private static final List<CustomPattern> patterns = Collections.synchronizedList(new ArrayList<>());

    public static void addPattern(String name, String regex, String severity) {
        patterns.add(new CustomPattern(name, regex, severity));
    }

    public static void removePattern(int index) {
        if (index >= 0 && index < patterns.size()) {
            patterns.remove(index);
        }
    }

    public static List<CustomPattern> getAll() {
        synchronized (patterns) {
            return new ArrayList<>(patterns);
        }
    }
}