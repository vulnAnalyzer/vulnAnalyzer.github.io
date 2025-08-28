package neu.lab.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import neu.lab.VulnInfo;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class GenJson {
    public void json(Map<String, Set<String>> res) {
        List<VulnInfo> vulnList = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : res.entrySet()) {
            String[] key = entry.getKey().split("@");
            vulnList.add(new VulnInfo(key[1], key[0], entry.getValue()));
        }
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.writerWithDefaultPrettyPrinter().writeValue(new File("VAScannerVulnerableAPI.json"), vulnList);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("finish");
    }
}
