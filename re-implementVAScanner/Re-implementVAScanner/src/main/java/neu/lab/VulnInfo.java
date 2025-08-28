package neu.lab;

import java.util.Set;

public class VulnInfo {
    public String cve_id;
    public String URL;
    public Set<String> api;

    public VulnInfo(String cve_id, String URL, Set<String> api) {
        this.cve_id = cve_id;
        this.URL = URL;
        this.api = api;
    }

}
