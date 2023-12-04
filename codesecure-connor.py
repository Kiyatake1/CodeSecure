import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess, os, threading, json, csv, git, shutil, pandas as pd, numpy

def check_installed_tools():
    installed_tools = []
    required_tools = ["bandit", "safety", "semgrep", "npm", "snyk"]

    for tool in required_tools:
        try:
            subprocess.run([tool, "--version"], capture_output=True, check=True)
            installed_tools.append(tool)
        except FileNotFoundError:
            pass  # Se o comando não for encontrado, o subprocesso lançará um FileNotFoundError

    return installed_tools

def start_installation():
    installed_tools = check_installed_tools()
    required_tools = ["bandit", "safety", "semgrep", "npm", "snyk"]
    missing_tools = [tool for tool in required_tools if tool not in installed_tools]

    if not missing_tools:
        messagebox.showinfo("Ferramentas Instaladas", "Todas as ferramentas necessárias já estão instaladas!")
    else:
        install_security_tools_async()

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
    Semgrep_file = "Analysis Report/semgrep_results.json"
    Bandit_file = "Analysis Report/bandit_results.json"

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

    # Salvar os resultados na pasta "relatórios"
    report_folder = "Analysis Report"
    os.makedirs(report_folder, exist_ok=True)  # Cria a pasta se ainda não existir

    # Salvar a planilha sumarizada
    sumarizado_path = os.path.join(report_folder, "sumarizado.csv")
    df.to_csv(sumarizado_path)

def clear_previous_analysis():
    # Caminho dos Arquivos
    semgrep_file = "Analysis Report/semgrep_results.json"
    bandit_file = "Analysis Report/bandit_results.json"
    safety_file = "Analysis Report/safety_results.json"
    snyk_file = "Analysis Report/snyk_results.json"
    sumarizado_file = "Analysis Report/sumarizado.csv"

    # Verificar e excluir os arquivos, se existirem
    if os.path.exists(semgrep_file):
        os.remove(semgrep_file)
    if os.path.exists(bandit_file):
        os.remove(bandit_file)
    if os.path.exists(safety_file):
        os.remove(safety_file)
    if os.path.exists(snyk_file):
        os.remove(snyk_file)
    if os.path.exists(sumarizado_file):
        os.remove(sumarizado_file)

def scan_local(path, selected_sast_tools, selected_sca_tools):
    clear_previous_analysis()
    os.chdir(path)
    print("Análise em andamento!")
    results = {}
    # Salvar os resultados na pasta "Relatórios"
    report_folder = "Analysis Report"
    os.makedirs(report_folder, exist_ok=True)  # Cria a pasta se ainda não existir
    if "Bandit" in selected_sast_tools:
        bandit_result = subprocess.run(["bandit", "-r", "--format", "json", "."], capture_output=True, text=True)
        bandit_output_path = os.path.join(report_folder, 'bandit_results.json')
        with open(bandit_output_path, 'w') as json_file:
            json_file.write(bandit_result.stdout)  # Salvando o resultado do Bandit diretamente como JSON

    if "Semgrep" in selected_sast_tools:
        semgrep_result = subprocess.run(["semgrep", "--json", "."], capture_output=True, text=True)
        semgrep_output_path = os.path.join(report_folder, 'semgrep_results.json')
        with open(semgrep_output_path, 'w') as json_file:
            json_file.write(semgrep_result.stdout)  # Salvando o resultado do Semgrep diretamente como JSON

    if "Safety" in selected_sca_tools:
        safety_result = subprocess.run(["safety", "check", "--output", "json"], capture_output=True, text=True)
        safety_output_path = os.path.join(report_folder, 'safety_results.json')
        with open(safety_output_path, 'w') as json_file:
            json_file.write(safety_result.stdout)  # Salvando o resultado do Safety diretamente como JSON

    if "Snyk" in selected_sca_tools:
        subprocess.run(['sudo', 'snyk', 'auth'])
        snyk_result = subprocess.run(['sudo', "snyk", "test", "--command=python3", "--all-projects", "--skip-unresolved", "--json"], capture_output=True, text=True)
        snyk_output_path = os.path.join(report_folder, 'snyk_results.json')
        with open(snyk_output_path, 'w') as json_file:
            json_file.write(snyk_result.stdout)  # Salvando o resultado do Snyk diretamente como JSON
    
def scan_github(repo_url, selected_sast_tools, selected_sca_tools):
    repo_name = repo_url.split('/')[-1].split('.git')[0]  # Extrai o nome do repositório do URL
    # Verificar se a pasta de destino já existe
    if os.path.exists(repo_name):
        try:
            shutil.rmtree(repo_name)  # Remove o diretório existente e todos os seus arquivos
        except Exception as e:
            messagebox.showwarning("Erro ao Remover Pasta", f"Ocorreu um erro ao remover a pasta existente: {e}")
            return
    git.Repo.clone_from(repo_url, repo_name)  # Clona o repositório com o nome extraído
    scan_local(repo_name, selected_sast_tools, selected_sca_tools)  # Executa a análise no repositório clonado

def create_gui():
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
        def perform_analysis(path):
            scan_local(path, selected_sast_tools, selected_sca_tools)
            sumariza()  # Chama a função para sumarizar após a verificação

            # Fechar a janela de análise em andamento após a conclusão da análise
            analysis_window.destroy()
            messagebox.showinfo("Análise Concluída", "A análise foi concluída com sucesso!")

        # Verificar se as ferramentas foram selecionadas
        if not selected_sast_tools and not selected_sca_tools:
            messagebox.showwarning("Ferramentas Não Selecionadas", "Por favor, selecione pelo menos uma ferramenta SAST ou SCA antes de iniciar a análise.")
            return
        else:
            installed_tools = check_installed_tools()
            required_tools = ["bandit", "safety", "semgrep", "npm", "snyk"]
            missing_tools = [tool for tool in required_tools if tool not in installed_tools]

            if missing_tools:
                missing_tools_str = ", ".join(missing_tools)
                messagebox.showwarning("Ferramentas Ausentes", f"As seguintes ferramentas estão ausentes: {missing_tools_str}. Por favor, instale-as primeiro.")
                return

        path = filedialog.askdirectory()
        analysis_window = tk.Toplevel()  # Criar nova janela para exibir a mensagem de análise em andamento
        analysis_window.title("Análise em Andamento")
        analysis_label = ttk.Label(analysis_window, text="Análise em andamento...")
        analysis_label.pack()

        # Chamar a função de análise em segundo plano para não bloquear a interface principal
        threading.Thread(target=perform_analysis, args=(path,)).start()


    def scan_github_with_tools():
        def perform_github_analysis(repo_url):
            if not selected_sast_tools and not selected_sca_tools:
                messagebox.showwarning("Ferramentas Não Selecionadas", "Por favor, selecione pelo menos uma ferramenta SAST ou SCA antes de iniciar a análise.")
                return
            else:
                installed_tools = check_installed_tools()
                required_tools = ["bandit", "safety", "semgrep", "npm", "snyk"]
                missing_tools = [tool for tool in required_tools if tool not in installed_tools]

                if missing_tools:
                    missing_tools_str = ", ".join(missing_tools)
                    messagebox.showwarning("Ferramentas Ausentes", f"As seguintes ferramentas estão ausentes: {missing_tools_str}. Por favor, instale-as primeiro.")
                    return

            if repo_url:
                analysis_window = tk.Toplevel()
                analysis_window.title("Análise em Andamento")
                analysis_label = ttk.Label(analysis_window, text="Análise em andamento...")
                analysis_label.pack()

                scan_github(repo_url, selected_sast_tools, selected_sca_tools)
                sumariza()  # Chama a função para sumarizar após a verificação

                analysis_window.destroy()
                messagebox.showinfo("Análise Concluída", "A análise foi concluída com sucesso!")
                github_window.destroy()
            else:
                messagebox.showwarning("URL Vazia", "Por favor, insira a URL do repositório GitHub.")

        github_window = tk.Toplevel()
        github_window.title("Análise de Repositório GitHub")

        github_label = ttk.Label(github_window, text="Insira a URL do repositório GitHub:")
        github_label.pack()

        github_entry = ttk.Entry(github_window, width=50)
        github_entry.pack()

        perform_github_button = ttk.Button(github_window, text="Analisar Repositório", command=lambda: perform_github_analysis(github_entry.get()))
        perform_github_button.pack()



    install_button = ttk.Button(root, text="Instalar Ferramentas de Segurança", command=start_installation)
    install_button.pack(pady=5)
    scan_local_button = ttk.Button(root, text="Escanear Pasta Local", command=scan_local_with_tools)
    scan_local_button.pack(pady=5)
    scan_github_button = ttk.Button(root, text="Escanear Repositório GitHub", command=scan_github_with_tools)
    scan_github_button.pack(pady=5)
    root.mainloop()

if __name__ == "__main__":
    create_gui()

