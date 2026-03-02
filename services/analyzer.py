from services.virus_total import get_virustotal_report 
def analyze_target(inp_type, inp):
    stats , label, score = get_virustotal_report(inp_type, inp)
    result = {
        "inp": inp,
        "stats": stats,
        "label" : label,
        "score": score
    }
    return result