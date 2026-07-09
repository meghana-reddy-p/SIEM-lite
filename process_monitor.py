import psutil

# Suspicious process names
SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "mimikatz.exe",
    "nmap.exe",
    "wireshark.exe"
]


def detect_suspicious_processes():

    suspicious_found = []

    for process in psutil.process_iter(['pid', 'name']):

        try:

            process_name = process.info['name']

            if process_name is not None:

                process_name = process_name.lower()

                if process_name in SUSPICIOUS_PROCESSES:

                    suspicious_found.append({

                        "pid": process.info['pid'],
                        "name": process_name

                    })

        except:

            continue

    return suspicious_found