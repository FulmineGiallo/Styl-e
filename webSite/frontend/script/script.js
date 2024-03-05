/*
	Method: Quando un file viene caricato all'interno del sito, deve comparire
	sulla textarea.
*/
document.getElementById('fileInput').addEventListener('change', function(event) {
	const fileInput = event.target;
	const file = fileInput.files[0];

	if (file) {
		const reader = new FileReader();

		reader.onload = function(e) {
			const content = e.target.result;

			try 
			{
				const yamlContent = jsyaml.load(content);
				console.log(content);
				document.getElementById('sigmaRulesTextarea').value = content;
			} 
			catch (error) {
				console.error('Errore durante il parsing del file YAML:', error);
			}
		};

		reader.readAsText(file);
	}
});

/*
	Ora mi serve che il contenuto della TextArea, una volta che il bottone "Traduci" viene cliccato,
	mandi il contenuto alla richiesta API per fare il parsing. 
*/


