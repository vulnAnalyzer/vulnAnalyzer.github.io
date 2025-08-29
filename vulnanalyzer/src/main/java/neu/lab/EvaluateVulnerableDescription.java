package neu.lab;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import neu.lab.llm.VulnerableDescriptionAnalyzer;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class EvaluateVulnerableDescription {
    static class VulnerableAPI {
        public String API;
        public String description;
    }

    static class VulnEntry {
        public String CWE;
        public String CVE;
        public List<VulnerableAPI> VulnerableAPI;
    }
        public static void main(String[] args) throws IOException {
        // 1. 读取merged.json文件内容
            // 1. 读取 merged.json 文件
            ObjectMapper mapper = new ObjectMapper();
            List<VulnEntry> entries = mapper.readValue(
                    Paths.get("E:\\code\\vulnAnalyzer\\merged.json").toFile(),
                    new TypeReference<List<VulnEntry>>() {}
            );
              // 2. 使用GPT判断CWE和CVE
            List<String> results = new ArrayList<>();
            for (VulnEntry entry : entries) {
                VulnerableDescriptionAnalyzer analyzer = new VulnerableDescriptionAnalyzer();
                for (VulnerableAPI vulnerableAPI : entry.VulnerableAPI) {
                    String res = analyzer.analyzeWithGPT(vulnerableAPI.API, vulnerableAPI.description, entry.CVE, entry.CWE);
                   results.add(res);
                }
            }
        // 3. 输出结果
            try (BufferedWriter writer = new BufferedWriter(new FileWriter("E:\\code\\vulnAnalyzer\\evaluatedVulnerableDescription.txt"))) {
                for (String line : results) {
                    writer.write(line);
                    writer.newLine(); // 换行
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
    }
}
