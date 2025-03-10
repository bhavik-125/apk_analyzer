import os
import json
import subprocess
from androguard.core.bytecodes.apk import APK
from lxml import etree

APKTOOL_PATH = "apktool"  


def analyze_apk(apk_path):
    """Extract metadata from the APK and analyze its structure."""
    print(f"[DEBUG] Checking if APK exists: {apk_path}")

    if not os.path.exists(apk_path):
        print(f"[ERROR] APK file not found: {apk_path}")
        return None

    print("[DEBUG] APK file exists. Loading with Androguard...")

    try:
        apk = APK(apk_path)
        print("[DEBUG] APK loaded successfully")

        print("[INFO] Extracting APK metadata...")
        apk_info = {
            "package_name": apk.package,
            "permissions": apk.get_permissions(),
            "activities": apk.get_activities(),
            "services": apk.get_services(),
            "receivers": apk.get_receivers(),
            "exported_components": extract_exported_components(apk)
        }

        print("[DEBUG] Extracted APK data successfully")
        return apk_info

    except Exception as e:
        print(f"[ERROR] Failed to analyze APK: {e}")
        return None






def extract_exported_components(apk):
    """Extract exported activities, services, and receivers by parsing AndroidManifest.xml"""
    exported_components = {
        "exported_activities": [],
        "exported_services": [],
        "exported_receivers": []
    }

    try:
        manifest_xml = apk.get_android_manifest_xml()
        if manifest_xml is None:
            print("[ERROR] Failed to parse AndroidManifest.xml")
            return exported_components

        manifest_str = etree.tostring(manifest_xml, encoding="utf-8").decode("utf-8")

        root = etree.fromstring(manifest_str)

        for component_type, tag_name in [
            ("exported_activities", "activity"),
            ("exported_services", "service"),
            ("exported_receivers", "receiver"),
        ]:
            for elem in root.findall(f".//{tag_name}"):
                component_name = elem.get("{http://schemas.android.com/apk/res/android}name")
                exported_attr = elem.get("{http://schemas.android.com/apk/res/android}exported")

                if exported_attr == "true" or (exported_attr is None and elem.find("intent-filter") is not None):
                    exported_components[component_type].append(component_name)

        return exported_components

    except Exception as e:
        print(f"[ERROR] Error extracting exported components: {e}")
        return exported_components

def check_security_risks(apk_info):
    """Analyze APK permissions and exported components for security risks."""
    print("[INFO] Analyzing security risks...")

    risky_permissions = {
        "android.permission.READ_SMS": "Can read SMS messages",
        "android.permission.SEND_SMS": "Can send SMS messages",
        "android.permission.READ_CONTACTS": "Can access contacts",
        "android.permission.RECORD_AUDIO": "Can record audio",
        "android.permission.CAMERA": "Can access the camera",
        "android.permission.ACCESS_FINE_LOCATION": "Can track location",
        "android.permission.QUERY_ALL_PACKAGES": "Can list all installed applications",
    }

    risks = []
    for perm in apk_info.get("permissions", []):
        if perm in risky_permissions:
            risks.append(f"⚠️ {perm}: {risky_permissions[perm]}")

  
    for category, components in apk_info["exported_components"].items():
        for component in components:
            risks.append(f"⚠️ Exported {category[:-1]}: {component} (Potential security risk)")

    print("[INFO] Security risk analysis complete.")
    return risks


def decompile_apk(apk_path, output_dir="decompiled_apk"):
    """Decompile APK using apktool."""
    print("[INFO] Decompiling APK using APKTool...")
    
    try:
        subprocess.run([APKTOOL_PATH, "d", apk_path, "-o", output_dir, "-f"], check=True)
        print("[SUCCESS] APK successfully decompiled.")
        return output_dir
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to decompile APK: {e}")
        return None


def run_static_analysis(decompiled_dir):
    """Run security analysis using Semgrep and Bandit."""
    print("[INFO] Running static security analysis...")

    results = {}

 
    try:
        semgrep_results = subprocess.run(["semgrep", "scan", "--config=auto", decompiled_dir],
                                         capture_output=True, text=True, check=True)
        results["semgrep"] = semgrep_results.stdout
    except Exception as e:
        results["semgrep"] = f"Error running Semgrep: {e}"

    try:
        bandit_results = subprocess.run(["bandit", "-r", decompiled_dir],
                                        capture_output=True, text=True, check=True)
        results["bandit"] = bandit_results.stdout
    except Exception as e:
        results["bandit"] = f"Error running Bandit: {e}"

    return results


def run_dynamic_analysis(apk_path):
    """Run Frida for runtime behavior analysis (optional)."""
    print("[INFO] Running Frida script for dynamic analysis...")
    try:
        result = subprocess.run(["frida", "-U", "-n", apk_path, "-e", "console.log('Frida Hooking APK')"],
                                capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        return f"[ERROR] Failed to run Frida: {e}"


def save_report(apk_info, security_risks, static_analysis_results, txt_report="apk_analysis_report.txt", json_report="security_report.json"):
    """Save APK analysis report in both text and JSON formats."""
    print("[INFO] Writing reports to file...")

    txt_data = f"""APK Analysis Report

Package Name: {apk_info['package_name']}

Permissions:
{chr(10).join(apk_info['permissions'])}

Activities:
{chr(10).join(apk_info['activities'])}

Services:
{chr(10).join(apk_info['services'])}

Receivers:
{chr(10).join(apk_info['receivers'])}

Exported Components:
{json.dumps(apk_info["exported_components"], indent=4)}

Security Risks:
{chr(10).join(security_risks)}

Static Analysis Results:
{json.dumps(static_analysis_results, indent=4)}
"""

    with open(txt_report, "w", encoding="utf-8") as f:
        f.write(txt_data)


    report_data = {
        "apk_info": apk_info,
        "security_risks": security_risks,
        "static_analysis_results": static_analysis_results
    }

    with open(json_report, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)

    print(f"[SUCCESS] Report saved as {txt_report} and {json_report}")


if __name__ == "__main__":
    print("[DEBUG] Script execution started in main block")

    apk_path = "/home/bhavik/Downloads/zarchiver-1-0-10.apk"  

    apk_info = analyze_apk(apk_path)

    if apk_info:
        security_risks = check_security_risks(apk_info)
        decompiled_dir = decompile_apk(apk_path)

        if decompiled_dir:
            static_analysis_results = run_static_analysis(decompiled_dir)
        else:
            static_analysis_results = {}

        save_report(apk_info, security_risks, static_analysis_results)

    print("[INFO] Analysis complete!")

