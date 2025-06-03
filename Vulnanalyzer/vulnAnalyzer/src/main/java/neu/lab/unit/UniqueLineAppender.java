package neu.lab.unit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;

public class UniqueLineAppender {
    private final static Logger log = LoggerFactory.getLogger(UniqueLineAppender.class);

    public boolean appendIfNotExists(String filePath, String input) throws IOException {
        Path path = Paths.get(filePath);

        // 确保文件存在
        if (!Files.exists(path)) {
            Files.createFile(path);
        }

        // 逐行读取并比较
        try (BufferedReader reader = Files.newBufferedReader(path)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.equals(input)) {
                    return false; // 已存在，不追加
                }
            }
        }

        // 如果文件中不存在该内容，则追加
        try (BufferedWriter writer = Files.newBufferedWriter(path, StandardOpenOption.APPEND)) {
            writer.write(input);
            writer.newLine();
        }
        log.info("Context Added!!!");
        return true;
    }
}

