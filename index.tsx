
// Declare JSZip - it will be loaded from CDN
declare const JSZip: any;

// --- DOM Elements ---
const form = document.getElementById('encryption-form') as HTMLFormElement;
const publicKeyInput = document.getElementById('public-key-input') as HTMLInputElement;
const selectFolderButton = document.getElementById('select-folder-button') as HTMLButtonElement;
const filesInput = document.getElementById('files-input') as HTMLInputElement;
const fileListElement = document.getElementById('file-list') as HTMLUListElement;
const fileCountError = document.getElementById('file-count-error') as HTMLParagraphElement;
const encryptButton = document.getElementById('encrypt-button') as HTMLButtonElement;
const statusArea = document.getElementById('status-area') as HTMLDivElement;
const statusMessage = document.getElementById('status-message') as HTMLParagraphElement;
const warningMessage = document.getElementById('warning-message') as HTMLParagraphElement;
const resultArea = document.getElementById('result-area') as HTMLDivElement;
const downloadLink = document.getElementById('download-link') as HTMLAnchorElement;
const resetButton = document.getElementById('reset-button') as HTMLButtonElement;

let selectedFiles: File[] = [];
let publicKeyPem: string | null = null; // Store PEM string

// --- Utility Functions ---

function updateStatus(message: string, showSpinner = true, showWarning = false) {
    statusMessage.textContent = message;
    statusArea.style.display = 'block';
    warningMessage.style.display = showWarning ? 'block' : 'none'; // Show/hide freeze warning
    const spinner = statusArea.querySelector('.spinner');
    if (spinner) {
        (spinner as HTMLElement).style.display = showSpinner ? 'block' : 'none';
    }
    resultArea.style.display = 'none';
    encryptButton.disabled = true;
}

function showResult(blobUrl: string) {
    statusArea.style.display = 'none';
    resultArea.style.display = 'block';
    downloadLink.href = blobUrl;
    encryptButton.disabled = true;
    form.style.display = 'none';
}

function showError(message: string) {
    statusMessage.textContent = `Error: ${message}`;
    warningMessage.style.display = 'none'; // Hide warning on error
    statusArea.style.display = 'block';
    const spinner = statusArea.querySelector('.spinner');
     if (spinner) {
        (spinner as HTMLElement).style.display = 'none';
    }
    resultArea.style.display = 'none';
    encryptButton.disabled = false;
    console.error(message);
}

function resetUI() {
    form.reset();
    selectedFiles = [];
    publicKeyPem = null;
    fileListElement.innerHTML = '';
    fileCountError.style.display = 'none';
    statusArea.style.display = 'none';
    resultArea.style.display = 'none';
    warningMessage.style.display = 'none';
    encryptButton.disabled = false;
    form.style.display = 'block';
}

// --- Encryption Functions (Moved from Worker) ---

function pemToArrayBuffer(pem: string): ArrayBuffer {
    const b64Lines = pem
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, '');
    const b64 = atob(b64Lines);
    const bytes = new Uint8Array(b64.length);
    for (let i = 0; i < b64.length; i++) {
        bytes[i] = b64.charCodeAt(i);
    }
    return bytes.buffer;
}

async function importRsaPublicKey(pem: string): Promise<CryptoKey> {
    const buffer = pemToArrayBuffer(pem);
    try {
         return await crypto.subtle.importKey('spki', buffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    } catch (e) {
        console.error("Error importing RSA key (SHA-256):", e);
        // Fallback attempt for SHA-1 if needed, though less common for public keys
        try {
            console.warn("Intentando importar llave RSA con SHA-1");
            return await crypto.subtle.importKey('spki', buffer, { name: 'RSA-OAEP', hash: 'SHA-1' }, true, ['encrypt']);
        } catch (e2) {
             console.error("Error importing RSA key (SHA-1):", e2);
             throw new Error(`Fallo al importar llave pública RSA: ${e} / ${e2}`);
        }
    }
}

async function encryptWithAes(data: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> {
    return await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, data);
}

async function encryptWithRsa(data: ArrayBuffer, publicKey: CryptoKey): Promise<ArrayBuffer> {
    return await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
}

// --- Main Encryption Process (Runs on Main Thread) ---
async function performEncryption() {
    if (!publicKeyPem || selectedFiles.length === 0) {
        showError("Faltan la llave pública o los archivos.");
        return;
    }

    updateStatus("Importando llave pública...", true, true); // Show warning
    let rsaPublicKey: CryptoKey;
    try {
        rsaPublicKey = await importRsaPublicKey(publicKeyPem);
    } catch (error: any) {
        showError(`Error al importar llave pública: ${error.message}`);
        return;
    }

    const results = [];
    const totalFiles = selectedFiles.length;

    for (let i = 0; i < totalFiles; i++) {
        const file = selectedFiles[i];
        const fileName = file.name;
        updateStatus(`Encriptando: ${fileName} (${i + 1}/${totalFiles})...`, true, true); // Show warning

        try {
            // Force UI update before potentially long operation
            await new Promise(resolve => setTimeout(resolve, 0));

            const fileBuffer = await file.arrayBuffer();
            const parts = fileName.split('.');
            const fileExtension = parts.length > 1 ? `.${parts.pop()}` : '';
            const extensionBuffer = new TextEncoder().encode(fileExtension);
            const extensionLengthBuffer = new ArrayBuffer(4);
            const view = new DataView(extensionLengthBuffer);
            view.setUint32(0, extensionBuffer.byteLength, false); // Big Endian

            const aesKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
            const aesKeyRaw = await crypto.subtle.exportKey('raw', aesKey);
            const iv = crypto.getRandomValues(new Uint8Array(16));

            const encryptedFileContent = await encryptWithAes(fileBuffer, aesKey, iv);
            const encryptedAesKey = await encryptWithRsa(aesKeyRaw, rsaPublicKey);

            const finalEncryptedFile = new Uint8Array([
                ...new Uint8Array(extensionLengthBuffer),
                ...extensionBuffer,
                ...iv,
                ...new Uint8Array(encryptedFileContent)
            ]).buffer;

            const baseName = fileName.substring(0, fileName.length - fileExtension.length);
            const encFileName = `${baseName}${fileExtension}.enc`;
            const keyFileName = `${baseName}${fileExtension}.key`;

            results.push({
                encFileName: encFileName,
                keyFileName: keyFileName,
                encryptedData: finalEncryptedFile,
                encryptedKey: encryptedAesKey
            });

        } catch (error: any) {
             showError(`Error encriptando ${fileName}: ${error.message}`);
             return; // Stop process on error
        }
    }

    // --- Create and Download Zip ---
    updateStatus('Encriptación finalizada. Creando archivo ZIP...', true, false); // Hide warning
     // Force UI update
    await new Promise(resolve => setTimeout(resolve, 0));

    try {
        const zip = new JSZip();
        results.forEach(result => {
            zip.file(result.encFileName, new Uint8Array(result.encryptedData));
            zip.file(result.keyFileName, new Uint8Array(result.encryptedKey));
        });

        const zipBlob = await zip.generateAsync({ type: 'blob' });
        const url = URL.createObjectURL(zipBlob);
        showResult(url);
    } catch (zipError: any) {
        showError(`Error al crear el archivo ZIP: ${zipError.message}`);
    }
}


// --- Event Listeners ---

publicKeyInput.addEventListener('change', async (event) => {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
        const file = input.files[0];
        try {
            updateStatus('Leyendo llave pública...', false); // No spinner here, it's fast
            publicKeyPem = await file.text();
            // Basic validation (optional)
            if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----') || !publicKeyPem.includes('-----END PUBLIC KEY-----')) {
                 throw new Error("Formato de llave pública inválido.");
            }
            updateStatus('Llave pública cargada.', false);
        } catch (error: any) {
            showError(`Error al leer la llave pública: ${error.message}`);
            publicKeyPem = null;
        }
    }
});

selectFolderButton.addEventListener('click', async () => {
    try {
        // @ts-ignore - Experimental API
        const dirHandle = await window.showDirectoryPicker();
        selectedFiles = [];
        fileListElement.innerHTML = '';
        fileCountError.style.display = 'none';
        let fileCount = 0;
        updateStatus('Leyendo archivos de la carpeta...', false); // No spinner needed here

        // @ts-ignore - Experimental API
        for await (const entry of dirHandle.values()) {
             if (entry.kind === 'file') {
                 if (fileCount >= 20) {
                     fileCountError.style.display = 'block';
                     showError('Se superó el límite de 20 archivos.');
                     selectedFiles = [];
                     fileListElement.innerHTML = '';
                     return;
                 }
                // @ts-ignore - Experimental API
                const file = await entry.getFile();
                selectedFiles.push(file);
                const listItem = document.createElement('li');
                listItem.textContent = file.name;
                fileListElement.appendChild(listItem);
                fileCount++;
            }
        }
         if (selectedFiles.length === 0) {
             showError('La carpeta seleccionada no contiene archivos.');
         } else {
              updateStatus(`Se seleccionaron ${selectedFiles.length} archivos.`, false);
         }

    } catch (err: any) {
         if (err instanceof DOMException && err.name === 'AbortError') {
            console.log('Selección de carpeta cancelada.');
            updateStatus('Selección cancelada.', false);
         } else {
            showError(`Error al seleccionar la carpeta: ${err.message || err}`);
            console.error('Error selecting folder:', err);
         }
    }
});

form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (!publicKeyPem) {
        showError('Por favor, selecciona un archivo de llave pública (.pem).');
        return;
    }
    if (selectedFiles.length === 0) {
        showError('Por favor, selecciona una carpeta con archivos para encriptar.');
        return;
    }
    if (selectedFiles.length > 20) {
        showError('No puedes encriptar más de 20 archivos a la vez.');
        return;
    }

    performEncryption(); // Call the main encryption function directly
});

resetButton.addEventListener('click', resetUI);

// --- Initial State ---
resetUI();


