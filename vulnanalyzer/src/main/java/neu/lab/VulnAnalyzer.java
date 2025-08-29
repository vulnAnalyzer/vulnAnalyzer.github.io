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

/**
 *
 * Workflow of VulnAnalyzer
 * 1. Read vulnerability information that includes patched versions.
 * 2. Identify vulnerable versions adjacent to the patched versions and download their source code packages.
 * 3. Use the abstract syntax tree (AST) to extract the code differences between the patched and adjacent vulnerable versions.
 * 4. Use a large language model (LLM) to identify vulnerable APIs.
 *
 * Configuration required when running the program:
 * 1. githubVulnerabilityFile: Configure the file path that stores the vulnerability information of patched versions.
 *    The default is demo.json. In our experiments, the vulnerability information used is in github_vulnerabilities.json.
 *    Since there are many vulnerability records and execution can be time-consuming, you can use demo.json first to quickly experience the workflow.
 *    Both demo.json and github_vulnerabilities.json are located in src/main/resources.
 *
 * 2. Configuration files in src/main/resources:
 *    -LLM.properties: set your API_KEY and API_URL.
 *
 * 3. downloadPath: The path for downloading the source code of patched and adjacent vulnerable versions.
 *
 */
public class VulnAnalyzer {
    private final static Logger log = LoggerFactory.getLogger(VulnAnalyzer.class);

    public static void main(String[] args) {
        ReadVulnerability readVulnerability = new ReadVulnerability();
        // 1. Retrieve the patched libraries from the vulnerability knowledge base
        // githubVulnerabilityFile: Configure the file path that stores the vulnerability information of patched versions
        String githubVulnerabilityFile = "demo.json";
        Map<String, Vulnerability> vulnerabilityMap = readVulnerability.getVulnerability(githubVulnerabilityFile);
        log.info("The patched libraries have been successfully loaded");


        // 2. Identify patches and adjacent vulnerable versions
        // downloadPath: The path for downloading the source code of patched and adjacent vulnerable versions
        String downloadPath = "E:\\work4\\patchTest";
        VulnerabilityDownloader vulnerabilityDownloader = new VulnerabilityDownloader();
        vulnerabilityDownloader.getPatchedAndVulnerableVersion(downloadPath);
        log.info("The source code of patched and adjacent vulnerable versions has been successfully downloaded");


        // 3. Compare the patch with the adjacent vulnerability version and extract the different code
        FileUtils fileUtils = new FileUtils();
        List<String[]> diffJars = fileUtils.readJarPaths("src/main/resources/downloadLog.log");
        JarDiffChecker jarDiffChecker = new JarDiffChecker();
        for (String[] diffJar : diffJars) {
            String oldJar = diffJar[1];
            String newJar = diffJar[0];
            jarDiffChecker.start(oldJar, newJar);
        }


        // 4. Use LLM to obtain vulnerability APIs
        File output = new File("src/main/resources/vulnAnalyzerResults/");
        // 所有存在变化的JARs
        File[] gavs = output.listFiles();
        SecurityPatchAnalyzer securityPatchAnalyzer = new SecurityPatchAnalyzer();
        String runLog = "src/main/resources/RunLog.log";
        Set<String> runFiles = new HashSet<>();
        ResourceFile resourceFile = new ResourceFile();
        if (new File(runLog).exists()) {
            runFiles.addAll(resourceFile.readRunFiles("src/main/resources/RunLog.log"));
        }
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
            List<VulnerableAPI> vulnerableAPIs = Collections.synchronizedList(new ArrayList<>());
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
                    resourceFile.writeToRunFiles(path, runLog);
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
                    log.info("Submitted task for file: " + path);
                }

            }

            // 收集所有 Future 的结果
            for (Future<Map<String, String>> future : futures) {
                try {
                    Map<String, String> result = future.get(); // 等待任务完成
                    if (result != null) {
                        for (Map.Entry<String, String> entry : result.entrySet()) {
                            String key = entry.getKey();
                            String[] split = key.split(">>>>>");
                            String operation = split[0];
                            String API = split[1];
                            String description = entry.getValue();
                            vulnerableAPIs.add(new VulnerableAPI(operation,API,description));
                        }
                    } else {
                        log.info("Task returned empty or null result.");
                    }
                } catch (Exception e) {
                    e.printStackTrace(); // 可以根据需要加日志记录失败项
                }
            }

            vulnerabilityInfo.getVulnerableAPI().addAll(vulnerableAPIs);
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
