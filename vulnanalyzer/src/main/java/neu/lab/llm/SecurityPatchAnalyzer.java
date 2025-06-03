package neu.lab.llm;

import neu.lab.unit.FileUtils;
import okhttp3.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class SecurityPatchAnalyzer {
    private final static Logger log = LoggerFactory.getLogger(SecurityPatchAnalyzer.class);
    private static final String API_KEY = "sk-zAfJoMNmQYtL67CgK0kcCZpWqACW6Y9g4L4Zwhauvnf7SBbD"; // littlewheat
    private static final String API_URL = "https://chatapi.littlewheat.com/v1/chat/completions";

    /**
     * 从漏洞版本和补丁版本前后删除或者新增的方法中,寻找漏洞API
     *
     * @return
     */
    //Todo
    public Map<String, String> deleteOrAddMethod(String filePath, boolean addMethod) {
        Map<String, String> result = new ConcurrentHashMap<>();
        FileUtils fileUtils = new FileUtils();
        // 提取方法代码
        String vulnerableMethod = null;
        try {
            vulnerableMethod = fileUtils.readFileContent(filePath);
            // 减小请求体
            String shortVulnerableMethod = vulnerableMethod.replaceAll("\\s+", " ").trim();
            SecurityPatchAnalyzer analyzer = new SecurityPatchAnalyzer();
            // 得到完全限定类名
            String className = analyzer.getClassName(filePath, addMethod);
            // 发送 GPT 请求进行安全分析
            result = analyzer.analyzeWithGPTAddOrDelete(shortVulnerableMethod, className, addMethod);
            if (result.isEmpty()) {
                log.info("结果为空");
            }
        } catch (IOException e) {
            log.info("deleteOrAddMethod: {}", e.getMessage());
        }
        return result;
    }

    /**
     * 从漏洞版本和补丁版本前后修改的方法中,寻找漏洞API
     *
     * @return
     */
    public Map<String, String> modifiedMethod(String patchedFilePath, String vulnerableFilePath) {
        Map<String, String> result = new ConcurrentHashMap<>();
        FileUtils fileUtils = new FileUtils();
        // 提取方法代码
        String vulnerableMethod = null;
        try {
            vulnerableMethod = fileUtils.readFileContent(vulnerableFilePath);
            String patchedMethod = fileUtils.readFileContent(patchedFilePath);
            // 减小请求体
            String shortVulnerableMethod = vulnerableMethod.replaceAll("\\s+", " ").trim();
            String shortPatchedMethod = patchedMethod.replaceAll("\\s+", " ").trim();
            SecurityPatchAnalyzer analyzer = new SecurityPatchAnalyzer();
            // 得到完全限定类名
            String className = analyzer.getClassName(patchedFilePath);
            // 发送 GPT 请求进行安全分析
            result = analyzer.analyzeWithGPT(shortVulnerableMethod, shortPatchedMethod, className);
            if (result.isEmpty()) {
                log.info("结果为空");
            }
        } catch (IOException e) {
            log.info("modifiedMethod: {}", e.getMessage());
        }
        return result;
    }


    // 发送 GPT 请求
    private Map<String, String> analyzeWithGPT(String vulnerableMethod, String patchedMethod, String className) throws IOException {
        Map<String, String> results = new ConcurrentHashMap<>();
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
        systemMessage.put("content", "You are a security expert with experience in analyzing code patches. Please logically deduce the security changes in the patch and determine whether the vulnerability has been fixed.");

        JSONObject userMessage = new JSONObject();
        userMessage.put("role", "user");
        userMessage.put("content", "Please do not refer to any previous content. Only use the current input below to make your judgment.### Vulnerable Method ###\n" + vulnerableMethod +
                "\n\n### Patched Method ###\n" + patchedMethod +
                "\n\n### Fully Qualified Class Name of the Method ###\n" + className +
                "\n\nAnalyze the code changes and determine if the patch has fixed the vulnerability. " +
                "If a vulnerability is fixed, output only the result in the following format and nothing else: " +
                "Vulnerable API: FullyQualifiedClassName:ReturnType:MethodName(ParameterTypes);Vulnerability Description:[brief description of the vulnerability]."
        );


        requestJson.put("messages", new org.json.JSONArray().put(systemMessage).put(userMessage));
        requestJson.put("temperature", 0.2);
        requestJson.put("thread_id", UUID.randomUUID().toString());  // 生成唯一会话 ID

        RequestBody body = RequestBody.create(requestJson.toString(), MediaType.get("application/json"));

        Request request = new Request.Builder()
                .url(API_URL)
//                .header("Authorization", "Bearer " + API_KEY1)
                .header("Authorization", "Bearer " + API_KEY)
                .header("Content-Type", "application/json")
                .post(body)
                .build();

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
            log.info("安全分析结果:\n{}", reply);
            try {
                String[] split = reply.replaceAll("[\\r\\n]+", "").split(";");
                String vulnerableAPI = "modified>>>>>" + split[0].replace("Vulnerable API:", "").trim();
                String vulnerabilityDescription = split[1].replace("Vulnerability Description:", "").trim();
                results.put(vulnerableAPI, vulnerabilityDescription);
            } catch (Exception e) {
                log.error("Error: {}", reply);
            }
        }
        return results;
    }

    // 发送 GPT 请求
    private Map<String, String> analyzeWithGPTAddOrDelete(String vulnerableMethod, String className, boolean addMethod) throws IOException {
        Map<String, String> results = new HashMap<>();
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(6000, TimeUnit.SECONDS) // 连接超时 60 秒
                .readTimeout(6000, TimeUnit.SECONDS)    // 读取超时 60 秒
                .writeTimeout(6000, TimeUnit.SECONDS)   // 写入超时 60 秒
                .build();

        // 构造 JSON 请求
        JSONObject requestJson = new JSONObject();
        requestJson.put("model", "gpt-4");
        // 构造对话内容
        JSONObject systemMessage = new JSONObject();
        systemMessage.put("role", "system");
        systemMessage.put("content", "You are a security expert specializing in vulnerability detection in code.");

        JSONObject userMessage = new JSONObject();
        userMessage.put("role", "user");
        userMessage.put("content",
                "Please do not refer to any previous content. Only use the current input below to make your judgment. ### Method Code ###\n" + vulnerableMethod +
                        "\n\n### Fully Qualified Class Name of the Method ###\n" + className +
                        "\n\nPlease analyze the above method and determine whether it contains a security vulnerability. " +
                        "If a vulnerability is found, output only the result in the following format and nothing else: " +
                        "Vulnerable API: FullyQualifiedClassName:ReturnType:MethodName(ParameterTypes);Vulnerability Description:[brief description of the vulnerability]."
        );

        requestJson.put("messages", new org.json.JSONArray().put(systemMessage).put(userMessage));
        requestJson.put("temperature", 0.2);
        requestJson.put("thread_id", UUID.randomUUID().toString());  // 生成唯一会话 ID

        RequestBody body = RequestBody.create(requestJson.toString(), MediaType.get("application/json"));
        String token = API_KEY;
        Request request = new Request.Builder()
                .url(API_URL)
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .post(body)
                .build();

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
            log.info("安全分析结果:\n{}", reply);
            try {
                String[] split = reply.replaceAll("[\\r\\n]+", "").split(";");
                String vulnerableAPI = split[0].replace("Vulnerable API:", "").trim();
                String vulnerabilityDescription = split[1].replace("Vulnerability Description:", "").trim();

                if (addMethod) {
                    vulnerableAPI = "added>>>>>" + vulnerableAPI;
                } else {
                    vulnerableAPI = "deleted>>>>>" + vulnerableAPI;
                }
                results.put(vulnerableAPI, vulnerabilityDescription);
            } catch (Exception e) {
                log.error("error: {}", reply);
            }
        }
        return results;
    }

    /**
     * 根据文件名获取完全限定类名
     *
     * @param filePath:文件名
     * @return 完全限定类名
     */
    private String getClassName(String filePath) {
        // 提取 "_" 之前的部分
        int underscoreIndex = filePath.indexOf("_");
        if (underscoreIndex == -1) {
            throw new IllegalArgumentException("Invalid file name format: " + filePath);
        }
        // 获取类名
        String packagePath = filePath.replace("\\", ".").replace("/", ".");

        // 找到 "modified.new." 之后的部分
        String identifier = "modified.new.";
        int startIndex = packagePath.indexOf(identifier);
        if (startIndex == -1) {
            throw new IllegalArgumentException("Unexpected package structure: " + packagePath);
        }
        return packagePath.substring(startIndex + identifier.length()).split("_")[0];

    }

    /**
     * 根据文件名获取完全限定类名
     *
     * @param filePath:文件名
     * @return 完全限定类名
     */
    private String getClassName(String filePath, boolean addMethod) {
        // 提取 "_" 之前的部分
        int underscoreIndex = filePath.indexOf("_");
        if (underscoreIndex == -1) {
            throw new IllegalArgumentException("Invalid file name format: " + filePath);
        }
        // 获取类名
        String packagePath = filePath.replace("\\", ".").replace("/", ".");
        String identifier = null;
        if (addMethod) {
            // 找到 "modified.new." 之后的部分
            identifier = "added.";
        } else {
            identifier = "deleted.";
        }
        int startIndex = packagePath.indexOf(identifier);
        if (startIndex == -1) {
            throw new IllegalArgumentException("Unexpected package structure: " + packagePath);
        }
        return packagePath.substring(startIndex + identifier.length()).split("_")[0];

    }
}

