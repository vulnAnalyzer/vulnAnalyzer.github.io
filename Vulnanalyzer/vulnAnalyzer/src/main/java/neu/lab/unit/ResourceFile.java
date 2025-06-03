package neu.lab.unit;

import neu.lab.VulnAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.URL;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

public class ResourceFile {
    private final static Logger log = LoggerFactory.getLogger(ResourceFile.class);

    public Set<String> readRunFiles(String fileName) {
        Set<String> lines = new LinkedHashSet<>();
        // 使用 BufferedReader 按行读取
        try (BufferedReader reader = new BufferedReader(new FileReader(fileName))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return lines;
    }

    public void writeToRunFiles(String content, String fileName) {
        // 获取资源文件 URL
        File file = new File(fileName);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file,true))) {
            writer.write(content);
            writer.newLine();
            log.info("RunFiles.txt written to: {}", content);
        } catch (Exception e) {
            log.info(e.getMessage());
        }
    }
}
