package neu.lab;


import neu.lab.utils.FileOperation;
import neu.lab.utils.GenJson;
import java.io.File;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 *The process of reproducing VAScanner in our paper is as follows:
 * (1) We crawled vulnerable APIs from patch commits in the GitHub Advisory Database and used them as the root vulnerable methods.
 * (2) Using Tai-e, we generated a call graph for each vulnerable library.
 * (3) We then took the root vulnerable methods as entry points and performed backward call-graph analysis on the call graph to obtain all vulnerable methods.
 * The results from step (1) are stored in the file vulnerableInformation.txt.
 *
 */

public class Re_implementVAScanner {
    public static void main(String[] args) {
        String vulnerableInformation = "src/main/resources/vulnerableInformation.txt";
        // vulnerableLibraryPath: The folder where the vulnerable libraries are located
        String vulnerableLibraryPath = "E:\\work4\\vulnerability";
        FileOperation fileOperation = new FileOperation();
        Set<String> inputs = fileOperation.readRunFiles(vulnerableInformation);
        Map<String, Set<String>> commits = new HashMap<>();
        for (String line : inputs) {
            String[] split = line.split(";");
            String key = split[0];
            String[] split1 = split[1].split(":");
            String name = split1[1] + "-" + split1[2];
            Set<String> apis = new HashSet<>();
            for (int i = 2; i < split.length; i++) {
                if (split[i].contains("@"))
                    continue;
                apis.add(split[i]);
            }
            commits.put(key + ";" + name, apis);
        }
        File path = new File(vulnerableLibraryPath);
        File[] files = path.listFiles();
        Map<String, Set<String>> res = new HashMap<>();
        Pattern pattern = Pattern.compile("\\b([a-zA-Z<>]+)\\s*\\(");
        for (File file : files) {
            if (file.isFile()) continue;
            String fileName = file.getName();
            File[] jarPaths = file.listFiles();
            Set<String> edges = new LinkedHashSet<>();
            Graph graph = new Graph();
            for (File jarPath : jarPaths) {
                if ("call-edges.txt".equals(jarPath.getName())) {
                    Set<String> runFiles = fileOperation.readRunFiles(jarPath.getAbsolutePath());
                    for (String line : runFiles) {
                        Matcher matcher = pattern.matcher(line);
                        String sourceMethod = null;
                        String targetMethod = null;
                        if (matcher.find()) {
                            sourceMethod = matcher.group(1);
                        }
                        while (matcher.find()) {
                            targetMethod = matcher.group(1); // 最后一个匹配
                        }
                        if (sourceMethod != null && targetMethod != null && !"init>".equals(targetMethod) && !"init>".equals(sourceMethod) && !"clinit>".equals(targetMethod) && !"cinit>".equals(sourceMethod) && !sourceMethod.equals(targetMethod)) {
                            edges.add(sourceMethod + " -> " + targetMethod);
                            graph.addEdge(sourceMethod, targetMethod);
                        }
                    }
                }
            }
            // 构造调用图
            Set<Map.Entry<String, Set<String>>> entries = commits.entrySet();
            for (Map.Entry<String, Set<String>> entry : entries) {
                String[] split = entry.getKey().split(";");
                String key = split[1];
                if (key.contains(fileName)) {
                    Set<String> value = entry.getValue();
                    Set<String> traverse = graph.traverse(value);
                    traverse.addAll(value);
                    if (res.containsKey(split[0])) continue;
                    res.put(split[0], traverse);
                } else {
                    Set<String> value = entry.getValue();
                    if (res.containsKey(split[0])) continue;
                    res.put(split[0], value);
                }
            }
        }
        GenJson json = new GenJson();
        json.json(res);
    }
}
