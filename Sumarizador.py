# This function extract the vulnerabilities and its severity level
import json
import pandas as pd
import numpy as np

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

# Caminho dos Arquivos
Semgrep_file = "v2.0.0.117_SG_results.json"
Bandit_file = "v2.0.0.117_bandit.json"

# Coletando os dados
vuls_S, severitys_S, lista_cwe_S, lista_code_S, lista_arquivos_S, lista_linhas_S  = extract_semgrep(Semgrep_file)
vuls_B, severitys_B, lista_cwe_B, lista_code_B, lista_arquivos_B, lista_linhas_B = extract_bandit(Bandit_file)

# Concatenando os dados
vulnerabilidades = vuls_S + vuls_B
severidades = severitys_S + severitys_B
cwes = lista_cwe_S + lista_cwe_B
codigos = lista_code_S + lista_code_B
arquivos = lista_arquivos_S + lista_arquivos_B
linhas =  lista_linhas_S + lista_linhas_B
print(len(vulnerabilidades),len(severidades),len(cwes),len(codigos),len(arquivos),len(linhas))

# Criando o dataframe
df = pd.DataFrame()
df["Vulnerabilidade"] = vulnerabilidades
df["CWE"] = cwes
df["Severidade"] = severidades
df["Código"] = codigos
df["Arquivo"] = arquivos
df["Linhas"] = linhas

df.to_csv("sumarizado.csv")


