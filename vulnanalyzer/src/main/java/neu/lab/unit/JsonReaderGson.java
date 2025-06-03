package neu.lab.unit;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.FileReader;

public class JsonReaderGson {
    private final static Logger log = LoggerFactory.getLogger(JsonReaderGson.class);

    public String readJson(String filePath) {
        JsonElement jsonElement = null;
        try {
            jsonElement = JsonParser.parseReader(new FileReader(filePath));
        } catch (FileNotFoundException e) {
            log.error(e.getMessage());
        }
        return new Gson().toJson(jsonElement);
    }
}

