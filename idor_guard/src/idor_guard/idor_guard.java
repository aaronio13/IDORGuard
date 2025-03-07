package idor_guard;

import java.awt.*;
import javax.swing.*;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

public class idor_guard {

    private JFrame frame;
    private JTextField urlField, usernameField, passwordField, depthField, startingPositionField, numberOfRoundsField;
    private JTextArea resultArea;
    private JButton startButton, loginButton, exportButton;
    private Map<String, String> cookies;
    private String storedUsername, storedPassword;
    private Set<String> idorParameters = new HashSet<>();
    private List<String> idorEntries = new ArrayList<>();

    public idor_guard() {
        frame = new JFrame("IDOR Guard");
        frame.setSize(600, 500);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(9, 2, 5, 5));

        urlField = new JTextField("http://test2214.sytes.net/index.php", 25);
        usernameField = new JTextField(15);
        passwordField = new JPasswordField(15);
        depthField = new JTextField("3", 3);
        startingPositionField = new JTextField("1", 3);
        numberOfRoundsField = new JTextField("10", 3);
        startButton = new JButton("Start Crawling");
        loginButton = new JButton("Login");
        exportButton = new JButton("Export log");

        panel.add(new JLabel("URL:"));
        panel.add(urlField);
        panel.add(new JLabel("Username:"));
        panel.add(usernameField);
        panel.add(new JLabel("Password:"));
        panel.add(passwordField);
        panel.add(new JLabel("Depth:"));
        panel.add(depthField);
        panel.add(new JLabel("Starting Position:"));
        panel.add(startingPositionField);
        panel.add(new JLabel("Number of Rounds (1-500):"));
        panel.add(numberOfRoundsField);
        panel.add(loginButton);
        panel.add(startButton);
        panel.add(exportButton);

        resultArea = new JTextArea();
        resultArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(resultArea);

        frame.add(panel, BorderLayout.NORTH);
        frame.add(scrollPane, BorderLayout.CENTER);

        loginButton.addActionListener(e -> login());
        startButton.addActionListener(e -> startCrawl());
        exportButton.addActionListener(e -> exportLog());

        frame.setVisible(true);

        loadDictionary("parameters.txt");
    }

    private void login() {
        if (!usernameField.getText().isEmpty() && !passwordField.getText().isEmpty()) {
            try {
                Connection.Response response = Jsoup.connect(urlField.getText())
                        .data("username", usernameField.getText())
                        .data("password", passwordField.getText())
                        .method(Connection.Method.POST)
                        .execute();

                // Store cookies and credentials
                cookies = response.cookies();
                storedUsername = usernameField.getText();
                storedPassword = passwordField.getText();

                if (cookies.isEmpty() || response.body().contains("Invalid username or password")) {
                    SwingUtilities.invokeLater(() -> resultArea.append("Login failed! Check credentials.\n"));
                } else {
                    SwingUtilities.invokeLater(() -> resultArea.append("Login successful!\n"));
                }
            } catch (IOException e) {
                SwingUtilities.invokeLater(() -> resultArea.append("Login request failed!\n"));
            }
        } else {
            SwingUtilities.invokeLater(() -> resultArea.append("Both username and password must be provided, skipping login.\n"));
        }
    }

    private void startCrawl() {
    	idorEntries.clear();
        resultArea.setText("");
        String url = urlField.getText();
        
        // Validate depth
        int depth;
        try {
            depth = Integer.parseInt(depthField.getText());
            if (depth < 1) {
                resultArea.setText("Depth must at least be 1.\n");
                return;
            }
        } catch (NumberFormatException ex) {
            resultArea.setText("Invalid depth value. Depth must at least be 1.\n");
            return;
        }

        // Validate starting position
        int startingPosition;
        try {
            startingPosition = Integer.parseInt(startingPositionField.getText());
            if (startingPosition < 1) {
                resultArea.setText("Starting Position must at least be 1.\n");
                return;
            }
        } catch (NumberFormatException ex) {
            resultArea.setText("Invalid starting position. Starting Position must at least be 1.\n");
            return;
        }

        // Validate number of rounds
        int numberOfRounds;
        try {
            numberOfRounds = Integer.parseInt(numberOfRoundsField.getText());
            if (numberOfRounds < 1 || numberOfRounds > 500) {
                resultArea.setText("Number of rounds must be between 1 and 500.\n");
                return;
            }
        } catch (NumberFormatException ex) {
            resultArea.setText("Invalid number of rounds. Number of rounds must be between 1 and 500.\n");
            return;
        }
        
        // Calculate Lower and Upper Limit
        int lowerLimit = startingPosition - numberOfRounds;
        if (lowerLimit < 1) { // Default to 1 if lowerLimit is negative
            lowerLimit = 1;
        }
        final int finalLowerLimit = lowerLimit;
        
        int upperLimit;
        if (startingPosition == 1) {
        	upperLimit = startingPosition + numberOfRounds - 1;
        } else {
        	upperLimit = startingPosition + numberOfRounds;
        }
        
     // Capture start time
        long startTime = System.currentTimeMillis();

        new Thread(() -> {
            crawl(1, url, depth, new ArrayList<>(), finalLowerLimit, upperLimit);

            // Calculate and display elapsed time
            long endTime = System.currentTimeMillis();
            long elapsedTime = endTime - startTime; // Time in milliseconds
            double seconds = elapsedTime / 1000.0; // Convert to seconds

            SwingUtilities.invokeLater(() -> resultArea.append(String.format("\n[+] Crawl completed!! (%.2fs)\n", seconds)));
        }).start();
    }

    private void crawl(int level, String url, int maxDepth, ArrayList<String> visited, int finalLowerLimit, int upperLimit) {
        if (level > maxDepth || visited.contains(url)) {
            return;
        }

        Document doc = request(url, visited);
        if (doc != null) {
            // Test URL parameter-based IDOR
            testIDOR(url, finalLowerLimit, upperLimit);
            // Search page for sensitive parameters
            searchForSensitiveParameters(doc, url);
            // Detect API endpoints (both static and dynamic) in inline JavaScript and test them
            detectAPIEndpoints(doc, finalLowerLimit, upperLimit);

            for (Element link : doc.select("a[href]")) {
                String nextLink = link.absUrl("href");
                crawl(level + 1, nextLink, maxDepth, visited, finalLowerLimit, upperLimit);
            }
        }
    }

    private Document request(String url, ArrayList<String> visited) {
        try {
            Connection con = Jsoup.connect(url);
            if (cookies != null && !cookies.isEmpty()) {
                con.cookies(cookies);
            }
            Document doc = con.get();
            if (con.response().statusCode() == 200) {
                SwingUtilities.invokeLater(() -> {
                    resultArea.append("Link: " + url + "\n");
                    resultArea.append(doc.title() + "\n\n");
                });
                visited.add(url);

                // Search for sensitive parameters in the page
                searchForSensitiveParameters(doc, url);

                // Check for login form and attempt auto-login if found
                if (doc.select("input[name=username]").size() > 0 && doc.select("input[name=password]").size() > 0) {
                    SwingUtilities.invokeLater(() -> resultArea.append("Login form detected, attempting to auto-login at: " + url + "\n"));
                    if (storedUsername != null && storedPassword != null) {
                        try {
                            Connection.Response loginResponse = Jsoup.connect(url)
                                    .data("username", storedUsername)
                                    .data("password", storedPassword)
                                    .method(Connection.Method.POST)
                                    .cookies(cookies)
                                    .followRedirects(true)
                                    .execute();

                            cookies.putAll(loginResponse.cookies());
                            String redirectedUrl = loginResponse.url().toString();
                            if (!redirectedUrl.equals(url)) {
                                SwingUtilities.invokeLater(() -> resultArea.append("Redirected to: " + redirectedUrl + "\n"));
                                return Jsoup.connect(redirectedUrl).cookies(cookies).get();
                            } else {
                                SwingUtilities.invokeLater(() -> resultArea.append("Login failed. Please check the login again.\n"));
                            }
                        } catch (IOException e) {
                            SwingUtilities.invokeLater(() -> resultArea.append("Auto-login failed at: " + url + "\n"));
                        }
                    }
                }
                return doc;
            }
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("Failed to fetch: " + url + "\n"));
        }
        return null;
    }

    // Test URL parameter-based IDOR
    private void testIDOR(String url, int finalLowerLimit, int upperLimit) {
        if (!url.contains("?")) {
            return;
        }
        try {
            String originalResponse = getHttpResponse(url);
            String[] parts = url.split("\\?");
            if (parts.length < 2) {
                return;
            }
            String base = parts[0];
            String query = parts[1];
    
            String[] params = query.split("&");
    
            for (String param : params) {
                String[] kv = param.split("=");
                if (kv.length != 2) {
                    continue;
                }
                String key = kv[0].toLowerCase();
                String originalValue = kv[1];
    
                if (idorParameters.contains(key)) { // Only test parameters in dictionary
                    SwingUtilities.invokeLater(() -> resultArea.append("[+] Testing IDOR on: " + url + "\n"));
                    for (int i = finalLowerLimit; i <= upperLimit; i++) {
                        String testUrl = base + "?" + key + "=" + i;
                        for (String otherParam : params) {
                            if (!otherParam.startsWith(key + "=")) {
                                testUrl += "&" + otherParam;
                            }
                        }
                        checkResponse(testUrl, originalResponse);
                    }
                }
            }
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("Error testing IDOR for: " + url + "\n"));
        }
    }
    
    // Test for API IDOR
    private void testAPIIDOR(String apiUrl, String method, String requestBody, int finalLowerLimit, int upperLimit) {
        if (!apiUrl.contains("?")) {
            return;
        }
        try {
            String[] parts = apiUrl.split("\\?");
            if (parts.length < 2) {
                return;
            }
            String base = parts[0];
            String query = parts[1];
    
            String[] params = query.split("&");
    
            for (String param : params) {
                String[] kv = param.split("=",-1);
                if (kv.length != 2) {
                    continue; // skip if not a valid key=value pair
                }
                
                String key = kv[0].toLowerCase();
                String originalValue = kv[1];
    
                if (idorParameters.contains(key)) {
                    // Get the baseline response using the valid baseline URL
                    String originalResponse = sendAPIRequest(apiUrl, method, requestBody);
                    SwingUtilities.invokeLater(() -> resultArea.append("[+] Testing API IDOR on: " + apiUrl + "\n"));
    
                    // Loop through possible parameter values (1 to 10)
                    for (int i = finalLowerLimit; i <= upperLimit; i++) {
                        String testUrl = base + "?" + key + "=" + i;
                        for (String otherParam : params) {
                            if (!otherParam.startsWith(key + "=")) {
                                testUrl += "&" + otherParam;
                            }
                        }
                        checkAPIResponse(testUrl, method, requestBody, originalResponse);
                    }
                }
            }
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("Error testing API IDOR for: " + apiUrl + "\n"));
        }
    }

    private String getHttpResponse(String url) throws IOException {
        Connection con = Jsoup.connect(url);
        if (cookies != null && !cookies.isEmpty()) {
            con.cookies(cookies);
        }
        return con.get().text();
    }

    private void checkResponse(String testUrl, String originalResponse) throws IOException {
        String testResponse = getHttpResponse(testUrl);
        if (!originalResponse.equals(testResponse) && !testResponse.toLowerCase().contains("user not found")) {
            String logEntry = "[!] Possible IDOR detected: " + testUrl;
            SwingUtilities.invokeLater(() -> {
                resultArea.append(logEntry + "\n");
                idorEntries.add(logEntry);
            });
        } else {
            SwingUtilities.invokeLater(() -> resultArea.append("[*] No valid data at: " + testUrl + "\n"));
        }
    }

    private void checkAPIResponse(String testUrl, String method, String requestBody, String originalResponse) throws IOException {
        String testResponse = sendAPIRequest(testUrl, method, requestBody);
        String lowerResponse = testResponse.toLowerCase();
        // Only flag if the response differs from baseline AND does not include typical error messages.
        if (!originalResponse.equals(testResponse) &&
            !lowerResponse.contains("user not found") &&
            !lowerResponse.contains("no valid data") &&
            !lowerResponse.contains("error")) {
            String logEntry = "[!] Possible API IDOR detected: " + testUrl;
            SwingUtilities.invokeLater(() -> {
                resultArea.append(logEntry + "\n");
                idorEntries.add(logEntry);
            });
        } else {
            SwingUtilities.invokeLater(() -> resultArea.append("[*] No valid data at: " + testUrl + "\n"));
        }
    }

    private String sendAPIRequest(String url, String method, String body) throws IOException {
        Connection con = Jsoup.connect(url).ignoreContentType(true);
        if (cookies != null && !cookies.isEmpty()) {
            con.cookies(cookies);
        }
        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method)) {
            con.requestBody(body).method(Connection.Method.valueOf(method.toUpperCase()));
        } else {
            con.method(Connection.Method.GET);
        }
        return con.execute().body();
    }

    // Scans inline JavaScript for API endpoints and tests them for IDOR vulnerabilities
    private void detectAPIEndpoints(Document doc, int finalLowerLimit, int upperLimit) {
        StringBuilder scriptContentAll = new StringBuilder();
        for (Element script : doc.select("script")) {
            scriptContentAll.append(script.html()).append("\n");
        }
        
        // Look for dynamic API endpoints
        Pattern dynamicPattern = Pattern.compile("fetch\\(['\"](https?://[^\"']+/api/[^\"']+\\?[^=]+=)['\"]\\s*\\+\\s*");
        Matcher dynamicMatcher = dynamicPattern.matcher(scriptContentAll.toString());
        while (dynamicMatcher.find()) {
            String partialUrl = dynamicMatcher.group(1);
            
            // Extract the parameter name from the URL
            String[] urlParts = partialUrl.split("\\?");
            if (urlParts.length < 2) {
                continue;
            }
            String[] params = urlParts[1].split("=");
            if (params.length < 1) {
                continue;
            }
            String paramName = params[0].toLowerCase();

            // Check if the parameter is in the idorParameters set
            if (idorParameters.contains(paramName)) {
                SwingUtilities.invokeLater(() -> resultArea.append("[*] Found dynamic API endpoint: " + partialUrl + "\n"));
                testAPIIDOR(partialUrl, "GET", null, finalLowerLimit, upperLimit);
            }
        }
    }

    private void searchForSensitiveParameters(Document doc, String url) {
        Set<String> detectedEntries = new HashSet<>();
        
        for (String param : idorParameters) {
            // Search for parameter inside forms
            for (Element form : doc.select("form")) {
                if (form.html().contains(param)) {
                    String formIdentifier = form.id().isEmpty() ? (form.attr("name").isEmpty() ? "Unnamed Form" : form.attr("name")) : form.id();
                    Element parentDiv = form.parent();
                    while (parentDiv != null && !parentDiv.tagName().equals("div")) {
                        parentDiv = parentDiv.parent();
                    }
                    String parentDivId = (parentDiv != null && !parentDiv.id().isEmpty()) ? parentDiv.id() : "No Parent Div";
                    String logEntry = "[!] Found " + param + " inside form: " + formIdentifier + ", Parent Div: " + parentDivId;
                    
                    if (!idorEntries.contains(logEntry)) { // Check against existing entries before adding
                        detectedEntries.add(logEntry);
                        SwingUtilities.invokeLater(() -> resultArea.append(logEntry + "\n"));
                        idorEntries.add(logEntry);
                    }
                }
            }

            // Search for parameter in input fields and elements
            for (Element element : doc.getAllElements()) {
                if (element.attr("name").equalsIgnoreCase(param) ||
                        element.attr("id").equalsIgnoreCase(param) ||
                        element.text().contains(param)) {
                    String logEntry = "[!] Found " + param + " in " +
                            (element.attr("name").isEmpty() ? element.attr("id") : element.attr("name")) + " at " + url;
                    
                    if (!idorEntries.contains(logEntry)) { // Check against existing entries before adding
                        detectedEntries.add(logEntry);
                        SwingUtilities.invokeLater(() -> resultArea.append(logEntry + "\n"));
                        idorEntries.add(logEntry);
                    }
                }
            }

            // Search for parameter in page text
            if (doc.text().toLowerCase().contains(param.toLowerCase())) {
                String logEntry = "[!] Found " + param + " in page text at " + url;
                
                if (!idorEntries.contains(logEntry)) { // Check against existing entries before adding
                    detectedEntries.add(logEntry);
                    SwingUtilities.invokeLater(() -> resultArea.append(logEntry + "\n"));
                    idorEntries.add(logEntry);
                }
            }
        }
    }

    public void exportLog() {
        if (idorEntries.isEmpty()) {
            SwingUtilities.invokeLater(() -> resultArea.append("[-] No IDOR vulnerabilities detected, nothing to export.\n"));
            return;
        }
        try (FileWriter writer = new FileWriter("IDOR_Report.csv")) {
            writer.append("IDOR Detected,Recommendation\n");
            for (String entry : idorEntries) {
                if (entry.contains("Possible IDOR detected") || entry.contains("Possible API IDOR detected")) {
                    writer.append("\"").append(entry).append("\",");
                    writer.append("\"Implement proper access control: Ensure users can only access their own data. Use Role-Based Access Control (RBAC).\"\n");
                } else if (entry.contains("Form")) {
                	writer.append("\"").append(entry).append("\",");
                    writer.append("\"Review form inputs: Ensure sensitive identifiers are not exposed unnecessarily in forms. Consider using session-based authentication.\"\n");
                }
            }
            SwingUtilities.invokeLater(() -> resultArea.append("[+] IDOR report exported successfully to IDOR_Report.csv\n"));
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("[-] Error exporting IDOR report: " + e.getMessage() + "\n"));
        }
    }

    private void loadDictionary(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                idorParameters.add(line.trim().toLowerCase());
            }
        } catch (IOException e) {
            SwingUtilities.invokeLater(() -> resultArea.append("[-] Error loading dictionary file.\n"));
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(idor_guard::new);
    }
}
