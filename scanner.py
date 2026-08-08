import os
import yara

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULE_PATH = os.path.join(BASE_DIR, "..", "rules", "test_rule.yara")

rules = yara.compile(filepath=RULE_PATH)

def scan_file(file_path):

    if not os.path.exists(file_path):
        return False, "File Not Found"

    try:
        matches = rules.match(file_path)

        if matches:
            rule_names = [match.rule for match in matches]
            return True, ", ".join(rule_names)

        return False, "No Malware Found"

    except Exception as e:
        return False, str(e)

