import paramiko
import os
import time
import re

LYNIS_PATH = "lynis"  # dossier local contenant lynis
REMOTE_PATH = "/tmp/lynis"  # dossier temporaire sur la machine distante

def strip_ansi_codes(text):
    """Remove ANSI color codes from text"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def read_credentials(file_path="ssh_credentials.txt"):
    if not os.path.exists(file_path):
        print(f"Fichier {file_path} introuvable.")
        exit(1)
    with open(file_path, "r") as f:
        lines = f.readlines()
        credentials = []
        for line in lines:
            parts = line.strip().split(";")
            if len(parts) == 3:
                credentials.append({
                    "host": parts[0],
                    "username": parts[1],
                    "password": parts[2]
                })
        return credentials

def check_lynis_folder():
    lynis_exec = os.path.join(LYNIS_PATH, "lynis")
    if not os.path.exists(lynis_exec):
        print(f"Le fichier {lynis_exec} est introuvable.")
        print("Assure-toi d'exécuter ce script dans le dossier contenant 'lynis/'.")
        exit(1)

def upload_lynis(sftp, local_path, remote_path):
    local_path = os.path.abspath(local_path)
    for root, dirs, files in os.walk(local_path):
        rel_path = os.path.relpath(root, local_path)
        remote_root = remote_path if rel_path == "." else os.path.join(remote_path, rel_path).replace("\\", "/")
        try:
            sftp.mkdir(remote_root)
        except:
            pass
        for file in files:
            local_file = os.path.join(root, file)
            remote_file = os.path.join(remote_root, file).replace("\\", "/")
            print(f"Fichier local : {local_file}")
            print(f"Destination distante : {remote_file}")
            sftp.put(local_file, remote_file)

def run_lynis(ssh_client, password, mode="normal"):
    print("Ajout des droits d'exécution sur Lynis distant ...")
    ssh_client.exec_command(f"chmod +x {REMOTE_PATH}/lynis")

    mode_flag = {
        "normal": "",
        "forensics": "--forensics",
        "integration": "--integration",
        "pentest": "--pentest"
    }.get(mode, "")

    # IMPORTANT: Ajouter --no-colors pour désactiver les codes ANSI
    cmd = f"echo '{password}' | sudo -S bash -c 'cd {REMOTE_PATH} && ./lynis audit system {mode_flag} --no-colors'"
    stdin, stdout, stderr = ssh_client.exec_command(cmd, get_pty=True)
    
    # Lire et nettoyer la sortie
    output = stdout.read().decode(errors='ignore') + stderr.read().decode(errors='ignore')
    return strip_ansi_codes(output)

def fetch_and_delete_logs(ssh_client, host, password):
    remote_files = {
        "/var/log/lynis.log": "lynis_log",
        "/var/log/lynis-report.dat": "lynis_report_dat"
    }

    timestamp = time.strftime("%Y%m%d-%H%M%S")

    for remote_path, prefix in remote_files.items():
        local_file = f"{prefix}_{host.replace('.', '_')}_{timestamp}.txt"
        try:
            print(f"Lecture distante avec sudo : {remote_path}")
            cmd = f"echo '{password}' | sudo -S cat {remote_path}"
            stdin, stdout, stderr = ssh_client.exec_command(cmd, get_pty=True)
            content = stdout.read().decode(errors='ignore') + stderr.read().decode(errors='ignore')
            
            # Nettoyer les codes ANSI
            content = strip_ansi_codes(content)

            with open(local_file, "w") as f:
                f.write(content)
            print(f"Fichier enregistré : {local_file}")

            print(f"Suppression de {remote_path} sur la machine distante ...")
            ssh_client.exec_command(f"echo '{password}' | sudo -S rm -f {remote_path}")

        except Exception as e:
            print(f"Erreur lors du traitement de {remote_path} : {e}")

def clean_remote(ssh_client):
    ssh_client.exec_command(f"rm -rf {REMOTE_PATH}")

def audit_machine(creds):
    host = creds["host"]
    username = creds["username"]
    password = creds["password"]

    print(f"\nConnexion à {host} ...")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=username, password=password, timeout=5)

        sftp = ssh.open_sftp()
        print("Transfert de Lynis ...")
        upload_lynis(sftp, LYNIS_PATH, REMOTE_PATH)

        print("Exécution de Lynis ...")
        audit_result = run_lynis(ssh, password, mode="forensics")

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        report_filename = f"rapport_lynis_{host.replace('.', '_')}_{timestamp}.txt"
        with open(report_filename, "w", encoding='utf-8') as f:
            f.write(audit_result)
        print(f"Rapport enregistré : {report_filename}")

        fetch_and_delete_logs(ssh, host, password)

        print("Nettoyage distant ...")
        clean_remote(ssh)

        ssh.close()
    except Exception as e:
        print(f"Erreur lors de l'audit de {host} : {e}")

def main():
    print("Dossier de travail :", os.getcwd())
    check_lynis_folder()
    credentials = read_credentials()
    for cred in credentials:
        audit_machine(cred)

if __name__ == "__main__":
    main()