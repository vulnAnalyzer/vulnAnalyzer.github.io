package neu.lab;

import neu.lab.llm.SecurityPatchAnalyzer;
import neu.lab.unit.FileUtils;
import neu.lab.unit.ResourceFile;
import neu.lab.vulnerability.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.*;
import java.util.concurrent.*;

public class VulnAnalyzer {
    private final static Logger log = LoggerFactory.getLogger(VulnAnalyzer.class);

    public static void main(String[] args) {
        ReadVulnerability readVulnerability = new ReadVulnerability();
        Map<String, Vulnerability> vulnerabilityMap = readVulnerability.getVulnerability();
        // 1. Identify patches and adjacent vulnerable versions
        VulnerabilityDownloader vulnerabilityDownloader = new VulnerabilityDownloader();
        vulnerabilityDownloader.getPatchedAndVulnerableVersion();
        // 2. Compare the patch with the adjacent vulnerability version and extract the different code
        FileUtils fileUtils = new FileUtils();
        List<String[]> diffJars = fileUtils.readJarPaths("src/main/resources/newPatchedPath.txt");
        JarDiffChecker jarDiffChecker = new JarDiffChecker();
        for (String[] diffJar : diffJars) {
            String oldJar = diffJar[1];
            String newJar = diffJar[0];
            jarDiffChecker.start(oldJar, newJar);
        }
        // 3. Use LLM to obtain vulnerability APIs
        File output = new File("E:\\work4\\test");
        // 所有存在变化的JARs
        File[] gavs = output.listFiles();
        SecurityPatchAnalyzer securityPatchAnalyzer = new SecurityPatchAnalyzer();
        ResourceFile resourceFile = new ResourceFile();
        Set<String> runFiles = resourceFile.readRunFiles("src/main/resources/RunFiles1.txt");
        OutPutVulnerability outPutVulnerability = new OutPutVulnerability();
        // 多线程池
        int maxThreads = 36;    // 同时运行的线程数
        int maxQueueSize = 30; // 等待队列大小

        ExecutorService executor = new ThreadPoolExecutor(
                maxThreads,
                maxThreads,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(maxQueueSize),
                new ThreadPoolExecutor.CallerRunsPolicy() // 超出就主线程执行，避免 OOM
        );
        VulnAnalyzer vulnAnalyzer = new VulnAnalyzer();
        for (File gav : gavs) {
            Map<String, String> vulnerableAPIs = new ConcurrentHashMap<>();
            File[] res = gav.listFiles();
            if (res == null) continue;

            String name = gav.getName();
            Vulnerability vulnerability = vulnerabilityMap.get(name);
            VulnerabilityInfo vulnerabilityInfo = new VulnerabilityInfo();
            vulnerabilityInfo.setVulnerability(vulnerability);

            List<Future<Map<String, String>>> futures = Collections.synchronizedList(new ArrayList<>());

            for (File re : res) {
                String operate = re.getName();
                if (operate.equals("modified")) {
                    File[] files = re.listFiles();
                    if (files == null) continue;
                    re = files[0];
                }

                List<File> actualFiles = vulnAnalyzer.collectAllFiles(re);
                for (File actualFile : actualFiles) {
                    String path = actualFile.getPath();
                    if (runFiles.contains(path)) continue;
                    runFiles.add(path);
                    resourceFile.writeToRunFiles(path, "src/main/resources/RunFiles1.txt");
                    Callable<Map<String, String>> task;

                    switch (operate) {
                        case "added":
                            task = () -> securityPatchAnalyzer.deleteOrAddMethod(path, true);
                            break;
                        case "deleted":
                            task = () -> securityPatchAnalyzer.deleteOrAddMethod(path, false);
                            break;
                        case "modified":
                            String vulnerablePath = path.replace(File.separatorChar + "new" + File.separatorChar,
                                    File.separatorChar + "old" + File.separatorChar);
                            task = () -> securityPatchAnalyzer.modifiedMethod(path, vulnerablePath);
                            break;
                        default:
                            continue; // 非法文件夹名，跳过
                    }

                    Future<Map<String, String>> future = executor.submit(task);
                    futures.add(future);
                    System.out.println("Submitted task for file: " + path);
                }

            }

            // 收集所有 Future 的结果
            for (Future<Map<String, String>> future : futures) {
                try {
                    Map<String, String> result = future.get(); // 等待任务完成
                    if (result != null) {
                        vulnerableAPIs.putAll(result);
                    } else {
                        System.out.println("Task returned empty or null result.");
                    }
                } catch (Exception e) {
                    e.printStackTrace(); // 可以根据需要加日志记录失败项
                }
            }

            vulnerabilityInfo.getVulnerableAPI().putAll(vulnerableAPIs);
            if (!vulnerabilityInfo.getVulnerableAPI().isEmpty()) {
                outPutVulnerability.writeAnalyze(vulnerabilityInfo);
            }
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(60, TimeUnit.MINUTES)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
        }
    }

    private List<File> collectAllFiles(File file) {
        List<File> files = new ArrayList<>();
        if (file.isFile()) {
            files.add(file);
        } else {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    files.addAll(collectAllFiles(child));
                }
            }
        }
        return files;
    }
}
