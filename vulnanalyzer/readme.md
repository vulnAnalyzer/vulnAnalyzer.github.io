# VulnAnalyzer

## Workflow

1. **Read vulnerability information** that includes patched versions.  
2. **Identify vulnerable versions adjacent to the patched versions** and download their source code packages.  
3. **Extract code differences** between the patched and adjacent vulnerable versions using the abstract syntax tree (AST).  
4. **Identify vulnerable APIs** using a large language model (LLM).  

## Configuration

When running the program, the following configurations are required:

1. Configuration variables **`githubVulnerabilityFile`**  
   - Configure the file path that stores the vulnerability information of patched versions.  
   Default: `demo.json`.  
   In experiments, the vulnerability information used is in `github_vulnerabilities.json`.  
   Since the number of vulnerability records is large and execution can be time-consuming, you can use `demo.json` first to quickly experience the workflow.  
   Both `demo.json` and `github_vulnerabilities.json` are located in: `src/main/resources`.

2. **Configuration files in `Resource`**  
   - `LLM.properties`: set your `API_KEY` and `API_URL`.

3. Configuration variables **`downloadPath`**  
   - The path for downloading the source code of patched and adjacent vulnerable versions.

## Running the Project
You can launch the project by running the main method: `VulnAnalyzer::main`


## Output

After running the program, the identified vulnerable APIs are saved in the file: `VulnAnalyzerVulnerableAPI.json`

The final results of VulnAnalyzer are saved to: `src/main/resources/VulnAnalyzerVulnerableAPI.json`