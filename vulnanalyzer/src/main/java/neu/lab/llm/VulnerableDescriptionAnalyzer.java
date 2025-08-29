package neu.lab.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import neu.lab.vulnerability.VulnerableVersion;
import okhttp3.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class VulnerableDescriptionAnalyzer {
    private final static Logger log = LoggerFactory.getLogger(VulnerableDescriptionAnalyzer.class);
    private static String API_KEY; // littlewheat
    private static String API_URL;

    public VulnerableDescriptionAnalyzer() {
        try (InputStream input = VulnerableVersion.class.getClassLoader().getResourceAsStream("LLM.properties");) {
            Properties properties = new Properties();
            properties.load(input);
            API_KEY = properties.getProperty("API_KEY");
            API_URL = properties.getProperty("API_URL");
        } catch (IOException e) {
            log.info("IOException");
        }
    }

    public String analyzeWithGPT(String api, String description, String CVE, String CWE) throws IOException {
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(60, TimeUnit.SECONDS) // 连接超时 60 秒
                .readTimeout(60, TimeUnit.SECONDS)    // 读取超时 60 秒
                .writeTimeout(60, TimeUnit.SECONDS)   // 写入超时 60 秒
                .build();

        // 构造 JSON 请求
        JSONObject requestJson = new JSONObject();
        requestJson.put("model", "gpt-4");
        // 构造对话内容
        JSONObject systemMessage = new JSONObject();
        systemMessage.put("role", "system");
        systemMessage.put("content", "You are a security expert specializing in source code vulnerability detection and classification. \n" +
                "Your task is to analyze the given vulnerable API and vulnerability description, and output the most likely CWE category \n" +
                "and, if possible, a matching CVE. \n" +
                "If no exact CVE is available, suggest the closest known CVE related to the vulnerability type and context.\n");

        JSONObject userMessage = new JSONObject();
        userMessage.put("role", "user");
        userMessage.put("content", "Please do not refer to any previous content. Only use the current input below to make your judgment." +
                "### Vulnerable API ###\n" + api +
                "\n\n### Vulnerability Description ###\n" + description +
                " Output only the result in the following format and nothing else: " +
                "CWE:[]; CVE:[]."
        );


        requestJson.put("messages", new JSONArray().put(systemMessage).put(userMessage));
        requestJson.put("temperature", 0.2);
        requestJson.put("thread_id", UUID.randomUUID().toString());  // 生成唯一会话 ID

        RequestBody body = RequestBody.create(requestJson.toString(), MediaType.get("application/json"));

        Request request = new Request.Builder()
                .url(API_URL)
                .header("Authorization", "Bearer " + API_KEY)
                .header("Content-Type", "application/json")
                .post(body)
                .build();
        String results = "";
        // 发送请求
        Response response = client.newCall(request).execute();
        // **检查 response.body() 是否为空**
        if (response.body() == null) {
            log.error("Error: API response body is null.");
            return results;
        } else {
            log.info("GPT返回代码: {}", response.code());
            String responseBody = response.body().string();
            // 解析 JSON 响应
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(responseBody);
            // **检查 API 返回是否包含数据**
            if (!rootNode.has("choices") || rootNode.get("choices").isEmpty()) {
                log.error("Error: OpenAI API response does not contain valid choices.");
                return results;
            }
            String reply = rootNode.path("choices").get(0).path("message").path("content").asText();
            log.info("API: {}", api);
            log.info("安全分析结果:{}", reply);
            try {
                // 正则提取 CWE
                Pattern cwePattern = Pattern.compile("CWE-\\d+");
                Matcher cweMatcher = cwePattern.matcher(reply);
                String cwe = cweMatcher.find() ? cweMatcher.group() : null;

                // 正则提取 CVE
                Pattern cvePattern = Pattern.compile("CVE-\\d{4}-\\d+");
                Matcher cveMatcher = cvePattern.matcher(reply);
                String cve = cveMatcher.find() ? cveMatcher.group() : null;
                String cweRes = "0";
                String cveRes = "0";
                if (CWE.equals(cwe)) {
                    cweRes = "1";
                }
                if (CVE.equals(cve)) {
                    cveRes = "1";
                }
                results = api + ";" + cweRes + ";" + cwe + ";" + cveRes + ";" + cve;
                return results;
            } catch (Exception e) {
                log.error("Error: {}", reply);
            }
        }
        return results;
    }
}
