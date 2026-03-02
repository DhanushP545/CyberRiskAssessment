import requests, base64, os
API_KEY = os.getenv("API_KEY")
base_url = "https://www.virustotal.com/api/v3"


def get_virustotal_report(inp_type, inp):
    if inp_type == 'hash':
        stats, label, score = analyze_file(inp)
    elif inp_type == 'url':
        stats, label, score = analyze_url(inp)
    else:
        stats, label, score = analyze_file(inp)
    return stats, label, score

def getData(url):
  vt_url = f"{base_url}/{url}"
  headers = {
      'x-apikey' : API_KEY
  }
  response = requests.get(vt_url, headers=headers)
  if(response.status_code==200):
    return response.json()
  print("Error : Couldn't fetch data")
  return None

def analyze_file(file_hash):

    data = getData(f"files/{file_hash}")

    if not data:
        return

    attributes = data["data"]["attributes"]

    stats = attributes["last_analysis_stats"]

    label, score = calculate_confidence(stats)

    print("\n--- FILE ANALYSIS ---")
    print("Detection Stats:", stats)
    print("Verdict:", label, f"({score}%)")
    print("\n--- BEHAVIOR INFORMATION ---")
    print("File Type:", attributes.get("type_description"))
    print("Threat Classification:",
          attributes.get("popular_threat_classification", {}))
    return stats, label, score
    
def analyze_url(url):

    url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data = getData(f"urls/{url}")

    if not data:
        return

    attributes = data["data"]["attributes"]

    stats = attributes["last_analysis_stats"]

    label, score = calculate_confidence(stats)

    print("\n--- URL ANALYSIS ---")
    print("Detection Stats:", stats)
    print("Verdict:", label, f"({score}%)")

    print("\n--- BEHAVIOR INFORMATION ---")
    print("URL Family:", attributes.get("url_family"))
    print("Threat Classification:",
          attributes.get("popular_threat_classification", {}))
    return stats, label, score

def analyze_ip(ip):

    data = getData(f"ip_address/{ip}")

    if not data:
        return

    attributes = data["data"]["attributes"]

    stats = attributes["last_analysis_stats"]

    label, score = calculate_confidence(stats)

    print("\n--- IP ANALYSIS ---")
    print("Country : ", attributes.get("country"))
    print("ASN : ", attributes.get("asn"))
    print("Detection Stats:", stats)
    print("Verdict:", label, f"({score}%)")
    return stats, label, score

def calculate_confidence(stats):
  malicious = stats.get("malicious",0)
  total = sum(stats.values())
  score = malicious/total

  if score<0.05:
    label = "likely safe.."
  elif score <0.25:
    label = "suspicious.."
  else:
    label = "malicious"
  return label, round(score*100,2)