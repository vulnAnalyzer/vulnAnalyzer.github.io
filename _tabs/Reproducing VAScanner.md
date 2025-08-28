---
icon: fas fa-tag
order: 4
title: Reproducing VAScanner
---

This project re-implements the workflow of **VAScanner** for automated vulnerable API detection.

---

## Download

1. Download the [Re-implementVAScanner](https://github.com/vulnAnalyzer/vulnAnalyzer.github.io/tree/main/re-implementVAScanner) code  
2. Download the vulnerable libraries: [vulnerable libraries](https://drive.google.com/drive/folders/1Y9OAoiSpWltF9wPnGntlLwpDe46hMebC?usp=drive_link)
3. Download the `Tai-e` installation package: [Tai-e](https://github.com/vulnAnalyzer/vulnAnalyzer.github.io/tree/main/re-implementVAScanner/Tai-e)
4. Download vulnerability information file: [vulnerableInformation.txt](https://github.com/vulnAnalyzer/vulnAnalyzer.github.io/blob/main/re-implementVAScanner/vulnerableInformation.txt)  

   - **Source:** [GitHub Advisory Database](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven)  
   - **Format of `vulnerableInformation.txt`:**  
     ```
     Vulnerability_Link@CVE_ID;Vulnerable_Library;Vulnerable_API@Library_Jar
     ```
   - **Example:**  
     ```
     https://github.com/advisories/GHSA-g6ph-x5wf-g337@CVE-2022-4244;org.codehaus.plexus:plexus-utils:3.0.23;extractFile;@plexus-utils-3.0.23.jar
     ```

---

## Installation

Install Tai-e: VAScanner uses **Tai-e** to build call graphs.  
   - For **Windows**:  [install.bat](https://github.com/vulnAnalyzer/vulnAnalyzer.github.io/blob/main/re-implementVAScanner/Tai-e/install.bat)
     
   - For **Linux**: [install](https://github.com/vulnAnalyzer/vulnAnalyzer.github.io/blob/main/re-implementVAScanner/Tai-e/install.sh) 
   
---

## Run

1. In the path of the vulnerable library, run **Tai-e** to generate the call graph (`call-edges.txt`) for each vulnerable library:  
   ```java
   mvn neu.lab:Tai-e-plugin:tai-e
   ```
2. Configure the paths of:

   - vulnerableLibraryPath: The folder where the vulnerable libraries are located

3. Run the `main` method to obtain the reproduced VAScanner vulnerable API file:
   
   - VAScannerVulnerableAPI.json

