#--------Import---------
from utils.validator import sanitize,detect_input_type
from modules.abuseipdb import query_abuseipdb
from modules.virustotal import query_virustotal
from modules.alienvault import query_otx
from config import Verdict


#----------Variables---------
SEVERITY = {
    "CLEAN":       0,
    "ERROR":       0,
    "UNSUPPORTED": 0,
    "SUSPICIOUS":  1,
    "MALICIOUS":   2,
}


#---------Appel des fonctions---------

def compare_verdict(result1, result2, result3):
    verdicts = [result1["verdict"], result2["verdict"], result3["verdict"]]
    return max(verdicts, key=lambda v: SEVERITY.get(v, 0))


def run_analysis(value): 

    #Validator
    sanitize_value = sanitize(value)
    detect_type = detect_input_type(sanitize_value)

    #Call API
    result_abuseipdb = query_abuseipdb(value,detect_type)
    result_virustotal = query_virustotal(value,detect_type)
    result_otx = query_otx(value,detect_type)


    #Verdict
    verdict = compare_verdict(result_abuseipdb,result_otx,result_virustotal)
    return {
        "value":           sanitize_value,
        "input_type":      detect_type,
        "overall_verdict": verdict,
        "sources": [result_virustotal, result_abuseipdb, result_otx]
    }



