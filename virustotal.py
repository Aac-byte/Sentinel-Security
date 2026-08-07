import requests
import time
import config


def scan_url_virustotal(url):
    headers = {
        "x-apikey": config.VT_API_KEY
    }

    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    print("Submit Status:", submit.status_code)

    if submit.status_code != 200:
        print("VirusTotal Error:", submit.text)
        return None

    analysis_id = submit.json()["data"]["id"]

    # Wait until VirusTotal finishes analysis
    for _ in range(10):

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        if report.status_code != 200:
            return None

        data = report.json()

        if data["data"]["attributes"]["status"] == "completed":
            return data

        time.sleep(2)

    return data


def scan_hash_virustotal(file_hash):

    headers = {
        "x-apikey": config.VT_API_KEY
    }

    report = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers=headers,
        timeout=15
    )

    print("===== HASH VT LOOKUP =====")
    print("Status:", report.status_code)

    if report.status_code == 200:
        return report.json()

    elif report.status_code == 404:
        print("Hash not found in VirusTotal.")
        return None

    else:
        print("VirusTotal Error:", report.text)
        return None


def scan_ip_virustotal(ip_address):

    headers = {
        "x-apikey": config.VT_API_KEY
    }

    report = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
        headers=headers,
        timeout=15
    )

    print("===== IP VT LOOKUP =====")
    print("Status:", report.status_code)

    if report.status_code == 200:
        return report.json()

    elif report.status_code == 404:
        print("IP address not found in VirusTotal.")
        return None

    else:
        print("VirusTotal Error:", report.text)
        return None


def scan_domain_virustotal(domain):

    headers = {
        "x-apikey": config.VT_API_KEY
    }

    report = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers=headers,
        timeout=15
    )

    print("===== DOMAIN VT LOOKUP =====")
    print("Status:", report.status_code)

    if report.status_code == 200:
        return report.json()

    elif report.status_code == 404:
        print("Domain not found in VirusTotal.")
        return None

    else:
        print("VirusTotal Error:", report.text)
        return None