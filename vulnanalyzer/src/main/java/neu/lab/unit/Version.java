package neu.lab.unit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

import static com.google.common.base.Preconditions.checkNotNull;

public class Version
{
    private static final Logger log = LoggerFactory.getLogger(Version.class);

    public static final String RESOURCE = "version.properties";

    public static final String UNKNOWN = "unknown";

    private final Class owner;

    Version(final Class owner) {
        this.owner = checkNotNull(owner);
    }

    private Properties load() {
        Properties result = new Properties();
        URL resource = owner.getResource(RESOURCE);
        if (resource == null) {
            log.warn("Missing resource: {}", RESOURCE);
        }
        else {
            log.debug("Resource: {}", resource);
            try {
                try (InputStream input = resource.openStream()) {
                    result.load(input);
                }
            }
            catch (Exception e) {
                log.warn("Failed to load resource: {}", RESOURCE, e);
            }
            log.debug("Properties: {}", result);
        }
        return result;
    }

    private Properties properties;

    private Properties properties() {
        if (properties == null) {
            properties = load();
        }
        return properties;
    }

    private String property(final String name) {
        String value = properties().getProperty(name);
        if (value == null || value.contains("${")) {
            return UNKNOWN;
        }
        return value;
    }

    public String getVersion() {
        return property("version");
    }

    public String getTimestamp() {
        return property("timestamp");
    }

    public String getTag() {
        return property("tag");
    }

    @Override
    public String toString() {
        return String.format("%s (%s; %s)", getVersion(), getTimestamp(), getTag());
    }

    public static Version get() {
        return new Version(Version.class);
    }
}
