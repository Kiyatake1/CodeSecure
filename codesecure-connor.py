import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess, os, threading, json, csv, git

def install_security_tools_async():
    install_security_tools()
    messagebox.showinfo("Instalação Concluída", "As ferramentas de segurança foram instaladas com sucesso!")

def install_security_tools():
    subprocess.run(['pip', 'install', 'bandit', 'safety', 'semgrep'])
    subprocess.run(['sudo', 'apt', 'install', 'npm'])
    subprocess.run(['sudo', 'npm', 'install', '-g', 'snyk'])

#Função de Conversão para Bandit
def convert_bandit_json_to_csv(bandit_json):
    csv_filename = 'bandit_report.csv'
    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['test_id', 'filename', 'line_number', 'issue_severity', 'issue_confidence', 'issue_text']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in bandit_json:
            writer.writerow({
                'test_id': result.get('test_id', ''),
                'filename': result.get('filename', ''),
                'line_number': result.get('line_number', ''),
                'issue_severity': result.get('issue_severity', ''),
                'issue_confidence': result.get('issue_confidence', ''),
                'issue_text': result.get('issue_text', ''),
            })

# Função de conversão para Semgrep
def convert_semgrep_json_to_csv(semgrep_json):
    csv_filename = 'semgrep_report.csv'

    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['check_id', 'path', 'start', 'end', 'lines', 'message']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for result in semgrep_json.get('results', []):
            writer.writerow({
                'check_id': result.get('check_id', ''),
                'path': result.get('path', ''),
                'start': result.get('start', {}).get('offset', ''),
                'end': result.get('end', {}).get('offset', ''),
                'lines': ', '.join(result.get('lines', [])),
                'message': result.get('message', ''),
            })
            
# Função de conversão para Safety
def convert_safety_json_to_csv(safety_json):
    csv_filename = 'safety_report.csv'

    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['vulnerability_id', 'package', 'installed', 'affected', 'description', 'references']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        vulnerabilities = safety_json.get('vulnerabilities', [])
        for vulnerability in vulnerabilities:
            writer.writerow({
                'vulnerability_id': vulnerability.get('vulnerability_id', ''),
                'package': vulnerability.get('package_name', ''),
                'installed': vulnerability.get('analyzed_version', ''),
                'affected': ', '.join(vulnerability.get('affected_versions', [])),
                'description': vulnerability.get('advisory', ''),
                'references': vulnerability.get('more_info_url', ''),
            })

# Função de conversão para Snyk
def convert_snyk_json_to_csv(snyk_json_list):
    csv_filename = 'snyk_report.csv'

    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['projectName', 'packageName', 'version', 'severity', 'title', 'from', 'upgradePath']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for project in snyk_json_list:
            for result in project.get('vulnerabilities', []):
                writer.writerow({
                    'projectName': project.get('projectName', ''),
                    'packageName': result.get('packageName', ''),
                    'version': result.get('version', ''),
                    'severity': result.get('severity', ''),
                    'title': result.get('title', ''),
                    'from': result.get('from', ''),
                    'upgradePath': ', '.join(result.get('upgradePath', [])),
                })

def scan_local(path, selected_sast_tools, selected_sca_tools):
    os.chdir(path)
    results = {}
    if "Bandit" in selected_sast_tools:
        bandit_result = subprocess.run(["bandit", "-r", "--format", "json", "."], capture_output=True, text=True)
        bandit_json = json.loads(bandit_result.stdout)
        results['bandit'] = bandit_json['results']
    if "Semgrep" in selected_sast_tools:
        semgrep_result = subprocess.run(["semgrep", "--json", "."], capture_output=True, text=True)
        semgrep_json = json.loads(semgrep_result.stdout)
        results['semgrep'] = semgrep_json
    if "Safety" in selected_sca_tools:
        safety_result = subprocess.run(["safety", "check", "--output", "json"], capture_output=True, text=True)
        safety_json = json.loads(safety_result.stdout)
        results['safety'] = safety_json
    if "Snyk" in selected_sca_tools:
        subprocess.run(['sudo', 'snyk', 'auth'])
        snyk_result = subprocess.run(['sudo',"snyk", "test", "--command=python3" "--all-projects", "--skip-unresolved", "--json"], capture_output=True, text=True)
        snyk_json = json.loads(snyk_result.stdout)
        results['snyk'] = snyk_json
        print(results['snyk'])
    for tool, result in results.items():
        if tool == 'bandit':
            convert_bandit_json_to_csv(result)
        elif tool == 'semgrep':
            convert_semgrep_json_to_csv(result)
        elif tool == 'safety':
            convert_safety_json_to_csv(result)
        elif tool == 'snyk':
            convert_snyk_json_to_csv(result)

def scan_github(repo_url, selected_sast_tools, selected_sca_tools):
    git.Repo.clone_from(repo_url, 'temp_folder')
    scan_local('temp_folder', selected_sast_tools, selected_sca_tools)
    shutil.rmtree('temp_folder')

def create_gui():
    def start_installation():
        if messagebox.askyesno("Instalar Ferramentas de Segurança", "Deseja instalar as ferramentas de segurança?"):
            install_thread = threading.Thread(target=install_security_tools_async)
            install_thread.start()

    root = tk.Tk()
    root.title("CodeSecure Connor")
    root.geometry("1200x400")
    style = ttk.Style()
    style.configure('TButton', background='#336699', foreground='white')
    frame = ttk.Frame(root)
    frame.pack(expand=True, fill='both', padx=20, pady=10)
    logo = tk.PhotoImage(file='CodeSecure Logo.png')
    header = ttk.Label(frame, image=logo, compound=tk.LEFT, anchor='center', padding=10)
    header.pack(side='left')
    usage_message = ("CodeSecure Connor detecta e aponta possíveis falhas de segurança. Além disso, "
                    "centraliza e organiza os resultados das análises de diversas ferramentas, participando do processo de DevSecOps "
                    "em seus projetos e aumentando a confiabilidade da análise.")
    message_frame = ttk.LabelFrame(frame, text="Descrição", labelanchor="n")
    message_frame.pack(side='left', padx=10, pady=5, fill='both', expand=True)
    message_label = ttk.Label(message_frame, text=usage_message, wraplength=300, foreground='black')
    message_label.pack(padx=10, pady=10)
    sast_frame = ttk.LabelFrame(frame, text="Ferramentas SAST")
    sast_frame.pack(side='left', padx=10, pady=5, fill='both', expand=True)
    sast_tools = ["Bandit", "Semgrep"]
    selected_sast_tools = []
    def select_sast_tool(tool):
        if tool in selected_sast_tools:
            selected_sast_tools.remove(tool)
        else:
            selected_sast_tools.append(tool)
    for idx, tool in enumerate(sast_tools):
        checkbox = ttk.Checkbutton(sast_frame, text=tool, command=lambda t=tool: select_sast_tool(t))
        checkbox.pack(anchor=tk.W)
    sca_frame = ttk.LabelFrame(frame, text="Ferramentas SCA")
    sca_frame.pack(side='left', padx=10, pady=5, fill='both', expand=True)
    sca_tools = ["Safety", "Snyk"]
    selected_sca_tools = []
    def select_sca_tool(tool):
        if tool in selected_sca_tools:
            selected_sca_tools.remove(tool)
        else:
            selected_sca_tools.append(tool)
    for idx, tool in enumerate(sca_tools):
        checkbox = ttk.Checkbutton(sca_frame, text=tool, command=lambda t=tool: select_sca_tool(t))
        checkbox.pack(anchor=tk.W)
    def scan_local_with_tools():
        path = filedialog.askdirectory()
        scan_local(path, selected_sast_tools, selected_sca_tools)
    def scan_github_with_tools():
        repo_url = input("Digite a URL do repositório GitHub: ")
        scan_github(repo_url, selected_sast_tools, selected_sca_tools)
    install_button = ttk.Button(root, text="Instalar Ferramentas de Segurança", command=start_installation)
    install_button.pack(pady=5)
    scan_local_button = ttk.Button(root, text="Escanear Pasta Local", command=scan_local_with_tools)
    scan_local_button.pack(pady=5)
    scan_github_button = ttk.Button(root, text="Escanear Repositório GitHub", command=scan_github_with_tools)
    scan_github_button.pack(pady=5)
    root.mainloop()

if __name__ == "__main__":
    create_gui()

