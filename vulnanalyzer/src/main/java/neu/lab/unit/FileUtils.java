package neu.lab.unit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class FileUtils {
    private final static Logger log = LoggerFactory.getLogger(FileUtils.class);

    //src/main/resources/patchedPath.txt中存放的是补丁路径和漏洞路径
    public List<String[]> readJarPaths(String filePath) {
        List<String[]> jarPathsList = new ArrayList<>();
        try {
            List<String> lines = Files.readAllLines(Paths.get(filePath));
            for (String line : lines) {
                String[] parts = line.split(";");
                if (parts.length == 3) {
                    jarPathsList.add(new String[]{parts[1], parts[2]});
                }
            }
        } catch (IOException e) {
            log.info(e.getMessage());
        }
        return jarPathsList;
    }

    // 读取文件内容
    public String readFileContent(String filePath) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filePath)));
    }
}
