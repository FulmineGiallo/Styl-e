var requestAPI="";

// Seleziona la textarea tramite l'ID (sostituisci 'idDellaTextarea' con l'ID effettivo)
const textarea = document.getElementById('sigmaRulesTextarea');

// Aggiungi un listener per l'evento 'input'
textarea.addEventListener('input', function()
{
    convertYamlToYara();
});

function update() 
{
    setTimeout(function () {
        // Ottieni il riferimento all'elemento input file
        var fileInput = document.getElementById('fileInput');

        // Verifica se è stato selezionato un file
        if (fileInput.files.length > 0) 
        {
            // Ottieni il primo file (consideriamo solo il primo anche se ne sono selezionati più di uno)
            var file = fileInput.files[0];

            // Usa FileReader per leggere il contenuto del file
            var reader = new FileReader();

            reader.onload = function (e) {
                // Aggiorna il contenuto del textarea con il contenuto del file
                var textArea = document.getElementById('textArea');
                textArea.value = e.target.result;

                // Nascondi il messaggio di attesa
                console.log("Operazione completata.");
            };

            // Leggi il file come testo
            reader.readAsText(file);
        }
        convertYamlToYara();
    }, 2000); // Ritardo di 2 secondi (puoi regolare il valore in millisecondi)
   
}


function leggiValori(arrayValori)
{
    var codiceHTML ="";
    
    for (var i = 0; i < arrayValori.length; i++) 
    {
        codiceHTML +=
            '<div class="userPane"> \n' +
            '<div class="detection"> \n' +
            '<label class="valori">' + arrayValori[i] + '</label> \n' +
            '</div> \n' +
            '<div class="userInputPane"> \n' +
            '<div class="userInput"> \n' +
            '<select id="sceltaValore" name="sceltaValore"> \n' +
            '<option value="principal">Principal</option> \n' +
            '<option value="target">Target</option> \n' +
            '<option value="about">About</option> \n' +
            '<option value="network">Network</option> \n' +
            '<option value="metadata">Metadata</option> \n' +
            '<option value="additional">Additional</option> \n' +
            '<option value="intermediary">Intermediary</option> \n' +
            '<option value="security_result">Security Result</option> \n' +
            '<option value="observer">Observer</option> \n' +
            '<option value="src">Src</option> \n' +
            '</select> \n' +
            '</div> \n' +
            '</div> \n' +
            '</div> \n';
    }
    
   
   return codiceHTML;
}

/*Prendo tutti i valori inseriti dall'utente e faccio la richiesta API */
function selettore()
{
    // Seleziona tutti gli elementi select all'interno di .userInput
    var selectElements = document.querySelectorAll('.userInput select');

    // Array per memorizzare i valori selezionati
    var valoriSelezionati = [];

    // Itera attraverso tutti gli elementi select
    selectElements.forEach(function(selectElement) 
    {
        // Ottieni il valore selezionato
        var valoreSelezionato = selectElement.value;

        // Aggiungi il valore all'array
        valoriSelezionati.push(valoreSelezionato);
    });

    return valoriSelezionati;
}


function convertYamlToYara()
{
	const yamlContent = document.getElementById('sigmaRulesTextarea').value;
    // Ottieni il testo YAML dal textarea
    var yamlText = document.getElementById("sigmaRulesTextarea").value;
    try 
    {
        // Converti YAML in JSON utilizzando js-yaml
        var jsonOutput = jsyaml.load(yamlText);
         // Estrai solo il campo "detection"
        var detectionOutput = jsonOutput.detection;
        //Esegui la funzione di estrazione
        var arrayValuesOutput = extractArrayValues(detectionOutput, []);
      

        //Visualizza l'output JSON nell'elemento specificato
        //document.getElementById("yaralTextArea").textContent = JSON.stringify(arrayValuesOutput, null, 2);
        

        //Con arrayValuesOutput ora bisogna creare tanti <div> per ogni valore contenuto nell'array
        codiceHTMLUser = leggiValori(arrayValuesOutput);
    
        // Otteniamo un riferimento all'elemento con la classe "inputUser"
        var inputUserElement = document.querySelector('.inputUser');

        // Aggiungiamo HTML dinamicamente utilizzando innerHTML
        inputUserElement.innerHTML = codiceHTMLUser;

        var array = selettore();


        //Formazione stringa per la richiesta API
        requestAPI = yamlContent + '\n' + 'INPUT_VALORI' + '=' + '[' + array + ']';
        console.log(requestAPI);
    } 
    catch (error) 
    {
        // Gestisci gli errori durante la conversione
        document.getElementById("yaralTextArea").textContent = "Errore durante la conversione: " + error.message;
    }

}

/* Richiesta API server */
function requestYara()
{
    const yamlContent = document.getElementById('sigmaRulesTextarea').value;
    // Ottieni il testo YAML dal textarea
    var yamlText = document.getElementById("sigmaRulesTextarea").value;
    try 
    {
        // Converti YAML in JSON utilizzando js-yaml
        var jsonOutput = jsyaml.load(yamlText);
         // Estrai solo il campo "detection"
        var detectionOutput = jsonOutput.detection;
        //Esegui la funzione di estrazione
        var arrayValuesOutput = extractArrayValues(detectionOutput, []);
    

        var array = selettore();


        //Formazione stringa per la richiesta API
        requestAPI = yamlContent + '\n' + 'INPUT_VALORI' + '=' + '[' + array + ']';
        console.log(requestAPI);
    } 
    catch (error) 
    {
        // Gestisci gli errori durante la conversione
        document.getElementById("yaralTextArea").textContent = "Errore durante la conversione: " + error.message;
    }
	if (requestAPI.trim() !== '') 
    {
		const formData = new FormData();
        formData.append('requestAPI', new Blob([requestAPI], { type: 'text/plain' }), 'requestAPI.txt');

		fetch('http://192.168.44.129:5000/convert1',
		{
			method: 'POST',
			body: formData
		})
		.then(response => 
		{
			if (!response.ok) {
				throw new Error('Errore durante la conversione' + response.status);
			}
			return response.text(); // Assume che il server restituisca il testo del file YARA
		})
		.then(yaraContent => {
			// Aggiorna il contenuto del textarea con il file YARA ricevuto
			document.getElementById('yaralTextArea').value = yaraContent;
            // Evidenzia la sintassi utilizzando Prism.js
            hljs.highlightElement(document.getElementById('yaralTextArea'));
		})
		.catch(error => {
			console.error('Errore:', error);
		});
	} 
	else 
	{
		console.error('Inserisci il contenuto YAML nel textarea.');
	}
}
function extractArrayValues(obj, outputArray) {
    for (var key in obj) {
        if (Array.isArray(obj[key])) {
            outputArray = outputArray.concat(obj[key]);
        } else if (typeof obj[key] === 'object') {
            outputArray = extractArrayValues(obj[key], outputArray);
        }
    }
    return outputArray;
}
