import yaml

# scrivere funzione che capisce sui parametri specificati dall'utente       
# metadata -> Event metadata such as timestamp, source product, etc
# network -> network details for protocols only
# principal -> the acting entity es client start a conncection
# target -> acted entity es server accept a conncetion

def recon_entity(user_entity):
    if user_entity == "metadata":
        event_udm_field="metadata"
    elif user_entity == "network":
        event_udm_field="network"
    elif user_entity == "principal":
        event_udm_field="principal"
    elif user_entity == "target":
        event_udm_field="target"
    elif user_entity == "security_result":
        event_udm_field="security_result"
    return event_udm_field
    
    #serve per correggere l'input quando ci sono i caratteri speciali
def escape_special_characters(yaml_string):
        yaml_string = yaml_string.replace('\\', '\\\\')
        return yaml_string

def clean_filename(yaml_string):
        yaml_string = yaml_string.replace('\\', "")
        return yaml_string

def mapper_udm_field(campo):
    if "filename" in campo.lower() or "file_name" in campo.lower() or "image" in campo.lower():
        campo=campo.replace('\\',"")
        campo = "file.names"
    elif "commandline" in campo.lower() or "command_line" in campo.lower():
        campo = "process.command_line"
    elif "url" in campo.lower():
        campo = "url "
    elif "path" in campo.lower():
        campo = "file.full_path "
    elif "port" in campo.lower() or "destination_port" in campo.lower():
        campo = "port"
    elif "client" in campo.lower() or "server" in campo.lower():
        campo = "platform_version"
    elif "timeframe" in campo.lower():
        campo = "user.time_off.interval.end_time.seconds"
    elif "timeframe" in campo.lower():
        campo = "user.time_off.interval.end_time.seconds"
    elif "eventid" in campo.lower() or "event_id" in campo.lower():
        campo = "rule_name"
    elif "providername" in campo.lower() or "provider_name" in campo.lower():
        campo = "product_name"
    elif "queryname" in campo.lower() or "query_name" in campo.lower():
        campo = "dns.questions.name"

    return campo
        
def clean_title(title):
    title=title.replace(" ", "_")
    title=title.replace("(", "")
    title=title.replace(")", "")
    return title

def clean_references(ref):
        convstring = " ".join(ref)
        convstring=convstring.replace("[", "")
        convstring=convstring.replace("]", "")
        convstring=convstring.replace("(", "")
        convstring=convstring.replace(")", "")
        return convstring


def extract_variables_from_selection(selection):
    variables = []
    for key, value in selection.items():
        if isinstance(value, dict):
            nested_variables = extract_variables_from_selection(value)
            variables.extend(nested_variables)
        else:
            variables.append((key, value))
    return variables

def convert_sigma_to_yara(rule_sigma,udm_field_list):
    try:
        # carica la sigma rule
        
        sigma_rule = yaml.safe_load(rule_sigma)

        # estrae i metadati dalla regola Sigma
        title = sigma_rule.get("title", "UnknownRuleTitle")
        # aggiusta il titolo con gli underscore per la sintassi di chronicle
        title=clean_title(title)
        rule_id = sigma_rule.get("id", "")
        description = sigma_rule.get("description", "")
        status = sigma_rule.get("status", "")
        author = sigma_rule.get("author", [])
        references = sigma_rule.get("references", [])
        references=clean_references(references)
        date = sigma_rule.get("date", "")
        modified = sigma_rule.get("modified", "")

        #fino ai metadati tutto apposto

        event_id = sigma_rule.get("logsource", {}).get("service", "")
        level = sigma_rule.get("level", "")
        false_positives = ', '.join(f'"{fp}"' for fp in sigma_rule.get("falsepositives", []))
        tags = ', '.join(f'"{tag}"' for tag in sigma_rule.get("tags", []))

        detection_variables = extract_variables_from_selection(sigma_rule.get("detection", {}))
        detection_variables = [(name, (value)) for name, value in detection_variables if name != "condition"]

        #vedere come impastare selection / o come si chiama
        # nuova regola YARA-L


        udm_entity=recon_entity("target")

        yara_rule = f'''
rule {title} {{
    meta:
        description = "{description} Author: {author}."
        rule_id = "{rule_id}"
        status = "{status}"
        severity = "{level.lower()}"
        references = "{references}"
        date = "{date}"
        modified = "{modified}"

    events:

       
'''
 
        yara_rule += f'     ('
        entity_byuser=""
        cntvar=0
        for variable_name, variable_value in detection_variables:
            i=0
            #print(variable_name,"->", variable_value)
            if(cntvar!=0): yara_rule += f' and'
            if "|contains|all" in variable_name:
                var_parts = variable_name.split('|')
                entity_byuser=udm_field_list[i]
                #entity_byuser=input("Inserisci il tipo di entità per " + var_parts[0] + " " )
                udm_entity=recon_entity(entity_byuser)
                udm_field=mapper_udm_field(var_parts[0])
                if isinstance(variable_value, (list, tuple)):
                    for val in variable_value:
                        yara_rule += f' re.regex($e.{udm_entity}.{udm_field}, `.* {val}.*`) '
                        if val != variable_value[-1]:
                            yara_rule += ' and'
                else: yara_rule += f' re.regex($e.{udm_entity}.{udm_field}, `.*{variable_value}.*`)'
            elif "|contains" in variable_name:
                var_parts = variable_name.split('|')
                entity_byuser=udm_field_list[i]
                #entity_byuser=input("Inserisci il tipo di entità per " + var_parts[0] + " ")
                udm_entity=recon_entity(entity_byuser)
                udm_field=mapper_udm_field(var_parts[0])
                if isinstance(variable_value, (list, tuple)):
                    for val in variable_value:
                        yara_rule += f' re.regex($e.{udm_entity}.{udm_field}, `.*{val}.*`)'   
                        if val != variable_value[-1]:
                            yara_rule += ' and'  
                else: yara_rule += f' re.regex($e.{udm_entity}.{udm_field}, `.*{variable_value}.*`)'
            elif "|endswith" in variable_name:
                var_parts = variable_name.split('|')
                entity_byuser=udm_field_list[i]
               # entity_byuser=input("Inserisci il tipo di entità per " + var_parts[0] + " ")
                udm_entity=recon_entity(entity_byuser)
                udm_field=mapper_udm_field(var_parts[0])
                if isinstance(variable_value, (list, tuple)):
                    for val in variable_value:
                        yara_rule += f' re.regex($e.{udm_entity}.{udm_field}, `.*{val}`)'
                        if val != variable_value[-1]:
                            yara_rule += ' and'
                else: yara_rule += f' re.regex($e.{udm_entity}.{udm_field}, `.*{variable_value}`)'
            elif "|startswith" in variable_name:
                var_parts = variable_name.split('|')
                entity_byuser=udm_field_list[i]
                #entity_byuser=input("Inserisci il tipo di entità per " + var_parts[0] + " ")
                udm_entity=recon_entity(entity_byuser)
                udm_field=mapper_udm_field(var_parts[0])
                if isinstance(variable_value, (list, tuple)):
                    for val in variable_value:
                        yara_rule += f' re.regex($e.{udm_entity}.{udm_field}, `{val}/.*`)'
                        if val != variable_value[-1]:
                            yara_rule += ' and'
                else:   yara_rule += f' re.regex($e.{udm_entity}.{udm_field}, `{variable_value}/.*`)'
            else: 
                    #entity_byuser=input("Inserisci il tipo di entità per " + variable_name )
                    entity_byuser=udm_field_list[i]
                    udm_entity=recon_entity(entity_byuser)
                    udm_field=mapper_udm_field(variable_name)
                    if(udm_entity=="security_result" and udm_field=="rule_name"):
                        yara_rule += f' $e.{udm_entity}.{udm_field} = "EventID: {variable_value}" '
                    elif isinstance(variable_value, (list, tuple)):
                            for val in variable_value:
                                yara_rule += f' $e.{udm_entity}.{udm_field} = "{val}" '
                    else: yara_rule += f' $e.{udm_entity}.{udm_field} = "{variable_value}" '


            i=i+1
            cntvar=cntvar + 1
        yara_rule += ')'
        
        yara_rule += '''
    
    condition:
'''

        yara_rule += f'    $e'

        yara_rule += '''
}
'''

        return yara_rule
    except Exception as e:
        print(f"Errore durante la conversione: {e}")
        return None


sigma_rule_example = r"""
title: Rclone SMB Share Exfiltration
id: 889bc648-5164-44f4-9388-fb5d6b58a7b2 
status: experimental
description: Detection of a exfiltration activity using rclone from Windows network shares using SMB.
author: TheDFIRReport
date: 2022/09/12
modified: 2023/01/08
references:
  - https://thedfirreport.com/
logsource:
  product: zeek
  service: smb_files
detection:
  selection:
    file_name|endswith:
      - '\rclone.exe'
  condition: selection
falsepositives:
  - Approved business backup processes.
level: medium
tags:
  - attack.exfiltration
  - attack.t567.002
"""
vet_udm=["target"]

sigma_rule_example=escape_special_characters(sigma_rule_example)
yara_rule = convert_sigma_to_yara(sigma_rule_example,vet_udm)
if yara_rule:
   # print("Regola YARA-L generata:\n")
    print(yara_rule)