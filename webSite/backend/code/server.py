import json
from flask import Flask, jsonify, request
from flask_cors import CORS  # Importa l'estensione CORS
import logging
import Parser
import yaml

app = Flask(__name__)
CORS(app) # Configura CORS per l'app Flask


@app.route('/test', methods=['GET'])
def test_connection():
    return '<html><body><h1>OK! Connessione riuscita.</h1></body></html>'

@app.route('/convert1', methods=['POST'])
def upload_file():
    try:

        uploaded_file = request.files['requestAPI']
        
        if uploaded_file:
            # Leggi il contenuto del file senza salvarlo
            file_content = uploaded_file.stream.read().decode('utf-8')

            #Estrai lista di input udm
            vet_udm= estrai_input_valori(file_content)
            #Estrai SIGMA
            sigma_rule_example = rimuovi_ultima_riga(file_content)
           
            #Formatto l'input in YML (Sigma)
            sigma_rule = stringa_a_yaml(sigma_rule_example)
            file_content = Parser.escape_special_characters(sigma_rule)
            yara_rule = Parser.convert_sigma_to_yara(sigma_rule,vet_udm)

            if yara_rule:
            # print("Regola YARA-L generata:\n")
                print(yara_rule)

            # Restituisci il contenuto del file come risposta

            return yara_rule
        else:
            return 'Errore: Nessun file ricevuto.', 400

    except Exception as e:
        return f'Errore durante il caricamento del file: {str(e)}', 500

def estrai_input_valori(sigma_rules):
    try:
        # Trova l'indice di inizio e fine della lista INPUT_VALORI
        start_index = sigma_rules.find("INPUT_VALORI=[")
        end_index = sigma_rules.find("]", start_index)

        # Se l'indice di inizio e fine sono validi, estrai la sottostringa
        if start_index != -1 and end_index != -1:
            input_valori_str = sigma_rules[start_index + len("INPUT_VALORI=["):end_index]
            # Rimuovi eventuali spazi bianchi e dividi gli elementi
            input_valori = [elemento.strip() for elemento in input_valori_str.split(",")]

            return input_valori
        else:
            return None

    except Exception as e:
        print(f"Errore durante l'estrazione della lista INPUT_VALORI: {e}")
        return None

def rimuovi_ultima_riga(input_string):
    # Dividi la stringa in righe
    righe = input_string.split('\n')
    
    # Rimuovi l'ultima riga
    nuova_stringa = '\n'.join(righe[:-1])
    
    return nuova_stringa 
def stringa_a_yaml(input_string):
    # Carica la stringa YAML
    dati_yaml = yaml.safe_load(input_string)
    
    # Restituisci i dati YAML formattati come stringa YAML
    return yaml.dump(dati_yaml, default_flow_style=False)
if __name__ == '__main__':
      print("Il server Flask sta per essere avviato.")
      app.run(host='0.0.0.0', port=5000)
      print("Il server Flask è stato avviato.")