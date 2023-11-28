import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import subprocess
import os
import git

def install_security_tools():
    subprocess.run(['pip', 'install', 'bandit', 'safety', 'pyre-check'])

def run_bandit(path):
    os.chdir(path)
    bandit_result = subprocess.run(["bandit", "-r", "."], capture_output=True, text=True)
    with open("bandit_report.txt", "w") as file:
        file.write(bandit_result.stdout)

def run_pyre(path):
    os.chdir(path)
    pyre_result = subprocess.run(["pyre", "--source-directory", "."], capture_output=True, text=True)
    with open("pyre_report.txt", "w") as file:
        file.write(pyre_result.stdout)

def run_safety(path):
    os.chdir(path)
    safety_result = subprocess.run(["safety", "check", "--full-report"], capture_output=True, text=True)
    with open("safety_report.txt", "w") as file:
        file.write(safety_result.stdout)

def run_dependency_check(path):
    os.chdir(path)
    dependency_check_script = os.path.join(path, "dependency-check.sh")
    if os.path.exists(dependency_check_script):
        dependency_check_result = subprocess.run([dependency_check_script, "--project", "."], capture_output=True, text=True)
        with open("dependency_check_report.txt", "w") as file:
            file.write(dependency_check_result.stdout)
    else:
        with open("dependency_check_report.txt", "w") as file:
            file.write("Script dependency-check.sh não encontrado na pasta especificada.")

def create_gui():
    root = tk.Tk()
    root.title("CodeSecure Connor")
    root.geometry("1200x400")

    # Adicionando uma cor de fundo para os frames e botões
    style = ttk.Style()
    style.configure('TButton', background='#336699', foreground='white')

    frame = ttk.Frame(root)
    frame.pack(expand=True, fill='both', padx=20, pady=10)

    # Alinhando o logo à esquerda
    logo = tk.PhotoImage(file='CodeSecure Logo.png')  # Substitua 'CodeSecure Logo.png' pelo caminho do seu arquivo de imagem
    header = ttk.Label(frame, image=logo, compound=tk.LEFT, anchor='center', padding=10)
    header.pack(side='left')

    # Criando um quadro para a mensagem de uso
    usage_message = ("CodeSecure Connor detecta e aponta possíveis falhas de segurança. Além disso, "
                    "centraliza e organiza os resultados das análises de diversas ferramentas, participando do processo de DevSecOps "
                    "em seus projetos e aumentando a confiabilidade da análise.")
    message_frame = ttk.LabelFrame(frame, text="Descrição", labelanchor="n")
    message_frame.pack(side='left', padx=10, pady=5, fill='both', expand=True)
    message_label = ttk.Label(message_frame, text=usage_message, wraplength=300, foreground='black')
    message_label.pack(padx=10, pady=10)


    sast_frame = ttk.LabelFrame(frame, text="Ferramentas SAST")
    sast_frame.pack(side='left', padx=10, pady=5, fill='both', expand=True)

    sast_tools = ["Bandit", "Pyre"]
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

    sca_tools = ["Safety", "DependencyCheck"]
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

    scan_local_button = ttk.Button(root, text="Escanear Pasta Local", command=scan_local_with_tools)
    scan_local_button.pack(pady=5)
    scan_github_button = ttk.Button(root, text="Escanear Repositório GitHub", command=scan_github_with_tools)
    scan_github_button.pack(pady=5)
    root.mainloop()

if __name__ == "__main__":
    create_gui()