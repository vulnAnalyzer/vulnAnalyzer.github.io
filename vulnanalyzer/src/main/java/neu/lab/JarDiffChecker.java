package neu.lab;

import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class JarDiffChecker {
    private final static Logger log = LoggerFactory.getLogger(JarDiffChecker.class);

    /**
     * 启动方法:找出两个Jar中修改、新增和删除的方法
     *
     * @param oldJar: 旧JAR的路径
     * @param newJar: 新JAR的路径
     */
    public void start(String oldJar, String newJar) {
        JarDiffChecker checker = new JarDiffChecker();
        String output = "E:/work4/newOutput/" + checker.extractArtifactId(newJar);
        try {
            checker.compareJars(oldJar, newJar, output);
        } catch (Exception e) {
            log.info(e.getMessage());
        }
    }

    private String extractArtifactId(String jarPath) {
        String jarName = Paths.get(jarPath).getFileName().toString();
        return jarName.replaceAll("(-sources)?\\.jar$", "");
    }

    private void compareJars(String oldJar, String newJar, String outputDir) throws Exception {
        Map<String, String> oldMethods = extractMethodsFromJar(oldJar);
        Map<String, String> newMethods = extractMethodsFromJar(newJar);

        Path addedPath = Paths.get(outputDir, "added");
        Path deletedPath = Paths.get(outputDir, "deleted");
        Path modifiedOldPath = Paths.get(outputDir, "modified", "old");
        Path modifiedNewPath = Paths.get(outputDir, "modified", "new");

        // 找到被删除的方法
        boolean deleted = false;  // 标记是否已创建目录
        boolean add = false;  // 标记是否已创建目录
        boolean modified = false;  // 标记是否已创建目录

        for (String methodSig : oldMethods.keySet()) {
            if (!newMethods.containsKey(methodSig)) {
                if (!deleted) {
                    Files.createDirectories(deletedPath);
                    deleted = true;
                }

                log.info("❌ Removed method: {}", methodSig);
                writeToFile(deletedPath.resolve(sanitizeFileName(methodSig) + ".java"), oldMethods.get(methodSig));
            }
        }

        // 找到修改的方法
        for (String methodSig : oldMethods.keySet()) {
            if (newMethods.containsKey(methodSig)) {
                String oldBody = oldMethods.get(methodSig);
                String newBody = newMethods.get(methodSig);
                if (!oldBody.equals(newBody)) {
                    if (!modified) {
                        Files.createDirectories(modifiedOldPath);
                        Files.createDirectories(modifiedNewPath);
                        modified = true;
                    }
                    log.info("🔄 Modified method: {}", methodSig);
                    writeToFile(modifiedOldPath.resolve(sanitizeFileName(methodSig) + ".java"), oldBody);
                    writeToFile(modifiedNewPath.resolve(sanitizeFileName(methodSig) + ".java"), newBody);
                }
            }
        }

        // 找到新增的方法
        for (String methodSig : newMethods.keySet()) {
            if (!oldMethods.containsKey(methodSig)) {
                if (!add) {
                    Files.createDirectories(addedPath);
                    add = true;
                }
                log.info("✅ Added method: {}", methodSig);
                writeToFile(addedPath.resolve(sanitizeFileName(methodSig) + ".java"), newMethods.get(methodSig));
            }
        }
    }

    private Map<String, String> extractMethodsFromJar(String jarPath) throws Exception {
        Map<String, String> methods = new HashMap<>();
        Path tempDir = Files.createTempDirectory("java_src");

        // 解压 JAR
        extractJar(jarPath, tempDir);
        ParserConfiguration config = new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_11);

        StaticJavaParser.setConfiguration(config);
        // 解析 Java 源码
        Files.walk(tempDir)
                .filter(Files::isRegularFile)
                .forEach(file -> {
                    try {
                        CompilationUnit cu = StaticJavaParser.parse(file);
                        String packageName = cu.getPackageDeclaration()
                                .map(pd -> pd.getName().toString() + ".")
                                .orElse("");

                        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(clazz -> {
                            String className = packageName + clazz.getNameAsString();

                            clazz.findAll(MethodDeclaration.class).forEach(method -> {
                                String returnType = method.getType().toString().replace("<", "0").replace(">", "0");
                                String methodName = method.getNameAsString();
                                String params = method.getParameters().toString(); // 保留原始参数格式

                                // 计算参数哈希
                                String paramHash = hashString(params);

                                // 生成方法唯一标识
                                String methodSig = String.format("%s_%s_%s_%s", className, returnType, methodName, paramHash);

                                String methodContent = cleanMethodBody(method.toString()); // 存完整方法代码

                                methods.put(methodSig, methodContent);
                            });
                        });
                    } catch (Exception e) {
                        log.error("❌ Error parsing file: {}", file, e);
                    }
                });

        return methods;
    }

    private void extractJar(String jarPath, Path outputDir) throws Exception {
        try (ZipFile zipFile = new ZipFile(jarPath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".java")) {
                    Path filePath = outputDir.resolve(entry.getName());
                    Files.createDirectories(filePath.getParent());
                    try (InputStream is = zipFile.getInputStream(entry)) {
                        Files.copy(is, filePath, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        }
    }

    private void writeToFile(Path filePath, String methodContent) {
        try {
            Files.createDirectories(filePath.getParent());
            try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
                writer.write(methodContent);
            }
        } catch (IOException e) {
            log.error("❌ Failed to write file: {}", filePath, e);
        }
    }

    /**
     * 只对参数列表进行哈希处理，保持其他部分不变
     */
    private String sanitizeFileName(String methodSig) {
        // 只哈希方法参数部分（最后一个 "_" 之后的内容）
        int lastUnderscore = methodSig.lastIndexOf("_");
        if (lastUnderscore == -1) {
            return methodSig.replaceAll("[^a-zA-Z0-9_.]", "_");
        }

        String prefix = methodSig.substring(0, lastUnderscore); // 类名、返回值、方法名
        String params = methodSig.substring(lastUnderscore + 1); // 参数列表哈希
        return prefix + "_" + hashString(params);
    }

    /**
     * 计算字符串的 SHA-256 哈希值
     */
    private String hashString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.substring(0, 16); // 取前16位，避免文件名过长
        } catch (Exception e) {
            log.error("❌ Failed to hash string: {}", input, e);
            return "hash_error";
        }
    }

    /**
     * 移除方法体中的所有注释
     */
    private String cleanMethodBody(String methodBody) {
        return methodBody.replaceAll("(?s)/\\*.*?\\*/", "")  // 删除块注释 /* ... */
                .replaceAll("//.*", "")             // 删除行内注释 // ...
                .replaceAll("(?s)/\\*\\*.*?\\*/", "") // 删除 Javadoc /** ... */
                .replaceAll("(?m)^[ \t]*\r?\n", ""); // 删除空行
    }
}
