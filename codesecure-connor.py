import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess, os, threading, json, csv, git, shutil, pandas as pd, numpy

def install_security_tools_async():
    install_security_tools()
    messagebox.showinfo("Instalação Concluída", "As ferramentas de segurança foram instaladas com sucesso!")

def install_security_tools():
    subprocess.run(['pip', 'install', 'bandit', 'safety', 'semgrep'])
    subprocess.run(['sudo', 'apt', 'install', 'npm'])
    subprocess.run(['sudo', 'npm', 'install', '-g', 'snyk'])

#Funções do Sumarizador
def extract_bandit(n_arquivo:str):
    arquivo = open(n_arquivo) # opening the JSON file
    data = json.load(arquivo) # returns JSON object as a dictionary

    lista_description = []
    lista_severity = []
    lista_CWE = []
    lista_code = []
    lista_file = []
    lista_line = []

    for analise in data["results"]:
        lista_description.append(analise["issue_text"])
        lista_severity.append(analise["issue_severity"])
        lista_code.append(analise["code"])
        lista_file.append(analise["filename"])
        lista_line.append(analise["line_number"])
        if analise["issue_cwe"]:
            lista_CWE.append(analise["issue_cwe"]["id"])
        else:
            lista_CWE.append("None")

    
    return lista_description, lista_severity, lista_CWE, lista_code, lista_file, lista_line

def extract_semgrep(n_arquivo:str):
    arquivo = open(n_arquivo) # opening the JSON file
    data = json.load(arquivo) # returns JSON object as a dictionary

    lista_description = []
    lista_severity = []
    lista_cwe = []
    lista_code = []
    lista_file = []
    lista_line = []

    for analise in data["results"]:
        lista_description.append(analise["extra"]["metadata"]["cwe"][0])
        lista_severity.append(analise["extra"]["metadata"]["impact"])
        lista_cwe.append(analise["extra"]["metadata"]["cwe"][0])
        lista_code.append(analise["extra"]["lines"])
        lista_file.append(analise["path"])
        lista_line.append(analise["start"]["line"])
    
    lista_cwe = [i[4:i.index(":")] for i in lista_cwe]
    lista_description = [i[i.index(":")+2:] for i in lista_description]
   

    return lista_description, lista_severity, lista_cwe, lista_code, lista_file, lista_line

def sumariza():
    # Caminho dos Arquivos
    Semgrep_file = "semgrep_results.json"
    Bandit_file = "bandit_results.json"

    # Coletando os dados
    vuls_S, severitys_S, lista_cwe_S, lista_code_S, lista_arquivos_S, lista_linhas_S = [], [], [], [], [], []
    vuls_B, severitys_B, lista_cwe_B, lista_code_B, lista_arquivos_B, lista_linhas_B = [], [], [], [], [], []

    if os.path.exists(Semgrep_file):
        vuls_S, severitys_S, lista_cwe_S, lista_code_S, lista_arquivos_S, lista_linhas_S = extract_semgrep(Semgrep_file)
    if os.path.exists(Bandit_file):
        vuls_B, severitys_B, lista_cwe_B, lista_code_B, lista_arquivos_B, lista_linhas_B = extract_bandit(Bandit_file)

    # Concatenando os dados
    vulnerabilidades = vuls_S + vuls_B
    severidades = severitys_S + severitys_B
    cwes = lista_cwe_S + lista_cwe_B
    codigos = lista_code_S + lista_code_B
    arquivos = lista_arquivos_S + lista_arquivos_B
    linhas = lista_linhas_S + lista_linhas_B

    # Imprimir informações formatadas
    print("Análise Completa!")
    print(f"Vulnerabilidades: {len(vulnerabilidades)}")
    print(f"Severidades: {len(severidades)}")
    print(f"CWEs: {len(cwes)}")
    print(f"Códigos: {len(codigos)}")
    print(f"Arquivos: {len(arquivos)}")
    print(f"Linhas: {len(linhas)}")
    print()

    # Criando o dataframe
    df = pd.DataFrame()
    df["Vulnerabilidade"] = vulnerabilidades
    df["CWE"] = cwes
    df["Severidade"] = severidades
    df["Código"] = codigos
    df["Arquivo"] = arquivos
    df["Linhas"] = linhas

    df.to_csv("sumarizado.csv")


def scan_local(path, selected_sast_tools, selected_sca_tools):
    os.chdir(path)
    results = {}
    if "Bandit" in selected_sast_tools:
        bandit_result = subprocess.run(["bandit", "-r", "--format", "json", "."], capture_output=True, text=True)
        with open('bandit_results.json', 'w') as csv_file:
            csv_file.write(bandit_result.stdout)  # Salvando o resultado do Bandit diretamente como CSV
    if "Semgrep" in selected_sast_tools:
        semgrep_result = subprocess.run(["semgrep", "--json", "."], capture_output=True, text=True)
        with open('semgrep_results.json', 'w') as json_file:
            json_file.write(semgrep_result.stdout)  # Salvando o resultado do Semgrep em um arquivo JSON
    if "Safety" in selected_sca_tools:
        safety_result = subprocess.run(["safety", "check", "--output", "json"], capture_output=True, text=True)
        with open('safety_results.json', 'w') as json_file:
            json_file.write(safety_result.stdout)  # Salvando o resultado do Safety em um arquivo JSON
    if "Snyk" in selected_sca_tools:
        subprocess.run(['sudo', 'snyk', 'auth'])
        snyk_result = subprocess.run(['sudo',"snyk", "test", "--command=python3" "--all-projects", "--skip-unresolved", "--json"], capture_output=True, text=True)
        with open('snyk_results.json', 'w') as json_file:
            json_file.write(snyk_result.stdout)  # Salvando o resultado do Snyk em um arquivo JSON
    
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
        sumariza()  # Chama a função para sumarizar após a verificação
        messagebox.showinfo("Análise Concluída", "A análise foi concluída com sucesso!")
    def scan_github_with_tools():
        repo_url = input("Digite a URL do repositório GitHub: ")
        scan_github(repo_url, selected_sast_tools, selected_sca_tools)
        sumariza()  # Chama a função para sumarizar após a verificação
        messagebox.showinfo("Análise Concluída", "A análise foi concluída com sucesso!")
    install_button = ttk.Button(root, text="Instalar Ferramentas de Segurança", command=start_installation)
    install_button.pack(pady=5)
    scan_local_button = ttk.Button(root, text="Escanear Pasta Local", command=scan_local_with_tools)
    scan_local_button.pack(pady=5)
    scan_github_button = ttk.Button(root, text="Escanear Repositório GitHub", command=scan_github_with_tools)
    scan_github_button.pack(pady=5)
    root.mainloop()

if __name__ == "__main__":
    create_gui()

