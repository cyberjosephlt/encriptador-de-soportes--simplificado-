

// Declare JSZip loaded from CDN
declare const JSZip: any;

// --- DOM Elements ---
const form = document.getElementById('encryption-form') as HTMLFormElement;
const publicKeyInput = document.getElementById('public-key-input') as HTMLInputElement;
const publicKeyStatus = document.getElementById('public-key-status') as HTMLParagraphElement;
const selectFolderButton = document.getElementById('select-folder-button') as HTMLButtonElement;
const filesInput = document.getElementById('files-input') as HTMLInputElement;
const fileListElement = document.getElementById('file-list') as HTMLUListElement;
const fileCountError = document.getElementById('file-count-error') as HTMLParagraphElement;
const folderStatus = document.getElementById('folder-status') as HTMLParagraphElement;
const encryptButton = document.getElementById('encrypt-button') as HTMLButtonElement;
const statusArea = document.getElementById('status-area') as HTMLDivElement;
const statusMessage = document.getElementById('status-message') as HTMLParagraphElement;
const errorMessage = document.getElementById('error-message') as HTMLParagraphElement; // Specific error message element
const warningMessage = document.getElementById('warning-message') as HTMLParagraphElement;
const spinner = document.getElementById('spinner') as HTMLDivElement;
const resultArea = document.getElementById('result-area') as HTMLDivElement;
const downloadLink = document.getElementById('download-link') as HTMLAnchorElement;
const resetButton = document.getElementById('reset-button') as HTMLButtonElement;

// --- State Variables ---
let selectedFiles: File[] = [];
let publicKeyPem: string | null = null;
let isPublicKeyLoaded = false;
let areFilesSelected = false;

// --- Utility Functions ---

function checkEnableEncryptButton() {
    encryptButton.disabled = !(isPublicKeyLoaded && areFilesSelected);
}

function updateStatus(
    message: string | null = null,
    options: { showSpinner?: boolean, isError?: boolean, showWarning?: boolean } = {}
) {
    const { showSpinner = false, isError = false, showWarning = false } = options;

    statusArea.style.display = message || showSpinner ? 'block' : 'none';
    statusMessage.textContent = message && !isError ? message : '';
    statusMessage.style.display = message && !isError ? 'block' : 'none';

    errorMessage.textContent = message && isError ? `Error: ${message}` : '';
    errorMessage.style.display = message && isError ? 'block' : 'none';

    if (spinner) spinner.style.display = showSpinner ? 'block' : 'none';
    warningMessage.style.display = showWarning ? 'block' : 'none';

    if (!message && !showSpinner) { // Hide everything if no message/spinner
         resultArea.style.display = 'none';
    } else if (!isError) {
         resultArea.style.display = 'none'; // Hide results when showing status/spinner (non-error)
    }
     // Keep encrypt button disabled while showing status unless it's just a success message without spinner
    encryptButton.disabled = showSpinner || (message !== null); // Keep disabled if showing any message or spinner

}

function showResult(blobUrl: string) {
    updateStatus(null); // Clear status area completely
    resultArea.style.display = 'block';
    downloadLink.href = blobUrl;
    encryptButton.disabled = true;
    form.style.display = 'none';
}

function showError(message: string) {
     updateStatus(message, { isError: true });
     encryptButton.disabled = false; // Re-enable button on error
     checkEnableEncryptButton(); // Re-check prerequisites after error clear might re-enable it
     console.error(message);
}


function resetUI() {
    form.reset();
    selectedFiles = [];
    publicKeyPem = null;
    isPublicKeyLoaded = false;
    areFilesSelected = false;
    fileListElement.innerHTML = '';
    fileCountError.style.display = 'none';
    publicKeyStatus.style.display = 'none';
    folderStatus.style.display = 'none';
    updateStatus(null); // Hide status area
    resultArea.style.display = 'none';
    encryptButton.disabled = true; // Start disabled
    form.style.display = 'block';
}

// --- Encryption Functions (No changes needed here) ---

function pemToArrayBuffer(pem: string): ArrayBuffer {
    const b64Lines = pem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace(/\s/g, '');
    const b64 = atob(b64Lines);
    const bytes = new Uint8Array(b64.length);
    for (let i = 0; i < b64.length; i++) bytes[i] = b64.charCodeAt(i);
    return bytes.buffer;
}

async function importRsaPublicKey(pem: string): Promise<CryptoKey> {
    const buffer = pemToArrayBuffer(pem);
    try {
         return await crypto.subtle.importKey('spki', buffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    } catch (e) { console.error("Error importing RSA key (SHA-256):", e); try { console.warn("Intentando importar llave RSA con SHA-1"); return await crypto.subtle.importKey('spki', buffer, { name: 'RSA-OAEP', hash: 'SHA-1' }, true, ['encrypt']); } catch (e2) { console.error("Error importing RSA key (SHA-1):", e2); throw new Error(`Fallo al importar llave pública RSA: ${e} / ${e2}`); } }
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

    // !! IMMEDIATE UI UPDATE BEFORE BLOCKING !!
    updateStatus("Encriptando...", { showSpinner: true, showWarning: true });
    // Force the UI to potentially update before the heavy work starts
    await new Promise(resolve => setTimeout(resolve, 0));

    let rsaPublicKey: CryptoKey;
    try {
        // This part is relatively fast
        rsaPublicKey = await importRsaPublicKey(publicKeyPem);
    } catch (error: any) {
        showError(`Error al importar llave pública: ${error.message}`);
        return; // showError already re-enables button check
    }

    const results = [];
    const totalFiles = selectedFiles.length;

    // !! HEAVY WORK STARTS HERE - UI WILL BE UNRESPONSIVE !!
    try {
        for (let i = 0; i < totalFiles; i++) {
            const file = selectedFiles[i];
            const fileName = file.name;

            // Update message, but spinner & warning remain
            updateStatus(`Encriptando: ${fileName} (${i + 1}/${totalFiles})...`, { showSpinner: true, showWarning: true });
             // Force UI update attempt before next file's blocking operations
             await new Promise(resolve => setTimeout(resolve, 0));

            const fileBuffer = await file.arrayBuffer(); // Reading file can take time
            const parts = fileName.split('.');
            const fileExtension = parts.length > 1 ? `.${parts.pop()}` : '';
            const extensionBuffer = new TextEncoder().encode(fileExtension);
            const extensionLengthBuffer = new ArrayBuffer(4);
            (new DataView(extensionLengthBuffer)).setUint32(0, extensionBuffer.byteLength, false);

            // Crypto operations are the most blocking parts
            const aesKey = await crypto.subtle.generateKey({ name: 'AES-CBC', length: 256 }, true, ['encrypt', 'decrypt']);
            const aesKeyRaw = await crypto.subtle.exportKey('raw', aesKey);
            const iv = crypto.getRandomValues(new Uint8Array(16));
            const encryptedFileContent = await encryptWithAes(fileBuffer, aesKey, iv);
            const encryptedAesKey = await encryptWithRsa(aesKeyRaw, rsaPublicKey);
            //---------------------------------------------------

            const finalEncryptedFile = new Uint8Array([...new Uint8Array(extensionLengthBuffer), ...extensionBuffer, ...iv, ...new Uint8Array(encryptedFileContent)]).buffer;
            const baseName = fileName.substring(0, fileName.length - fileExtension.length);
            const encFileName = `${baseName}${fileExtension}.enc`;
            const keyFileName = `${baseName}${fileExtension}.key`;

            results.push({ encFileName, keyFileName, encryptedData: finalEncryptedFile, encryptedKey: encryptedAesKey });
        }
        // !! HEAVY WORK ENDS HERE !!

    } catch (error: any) {
         const fileName = selectedFiles[results.length]?.name || 'archivo desconocido'; // Get current file name if possible
         showError(`Error encriptando ${fileName}: ${error.message}`);
         return; // Stop process on error
    }


    // --- Create and Download Zip (Can also take some time) ---
    updateStatus('Creando archivo ZIP...', { showSpinner: true, showWarning: false }); // Still processing, hide freeze warning
    await new Promise(resolve => setTimeout(resolve, 0)); // UI update attempt

    try {
        const zip = new JSZip();
        results.forEach(result => {
            zip.file(result.encFileName, new Uint8Array(result.encryptedData));
            zip.file(result.keyFileName, new Uint8Array(result.encryptedKey));
        });

        const zipBlob = await zip.generateAsync({ type: 'blob' });
        const url = URL.createObjectURL(zipBlob);
        showResult(url); // This hides the status area
    } catch (zipError: any) {
        showError(`Error al crear el archivo ZIP: ${zipError.message}`);
    }
}


// --- Event Listeners ---

publicKeyInput.addEventListener('change', async (event) => {
    const input = event.target as HTMLInputElement;
    isPublicKeyLoaded = false; // Reset flag
    publicKeyStatus.style.display = 'none'; // Hide status
    if (input.files && input.files.length > 0) {
        const file = input.files[0];
        try {
            // Don't show status here, just process
            publicKeyPem = await file.text();
            if (!publicKeyPem.includes('-----BEGIN PUBLIC KEY-----') || !publicKeyPem.includes('-----END PUBLIC KEY-----')) {
                 throw new Error("Formato de llave pública inválido.");
            }
            isPublicKeyLoaded = true;
            publicKeyStatus.style.display = 'block'; // Show success message
             showError(null); // Clear previous errors if any
        } catch (error: any) {
            showError(`Error al leer llave pública: ${error.message}`);
            publicKeyPem = null;
        }
    }
    checkEnableEncryptButton(); // Check if button should be enabled
});

selectFolderButton.addEventListener('click', async () => {
    areFilesSelected = false; // Reset flag
    folderStatus.style.display = 'none'; // Hide status
    fileListElement.innerHTML = ''; // Clear list display
    fileCountError.style.display = 'none';
    try {
        // @ts-ignore - Experimental API
        const dirHandle = await window.showDirectoryPicker();
        selectedFiles = [];
        let fileCount = 0;
        // Don't show status here, just process
        // @ts-ignore - Experimental API
        for await (const entry of dirHandle.values()) {
             if (entry.kind === 'file') {
                 if (fileCount >= 20) {
                     fileCountError.style.display = 'block';
                     showError('Se superó el límite de 20 archivos.');
                     selectedFiles = []; fileListElement.innerHTML = ''; areFilesSelected = false; // Ensure flag is false
                     checkEnableEncryptButton();
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
         if (selectedFiles.length > 0) {
            areFilesSelected = true;
            folderStatus.textContent = `${selectedFiles.length} archivo(s) seleccionado(s).`;
            folderStatus.style.display = 'block';
             showError(null); // Clear previous errors if any
         } else {
              showError('La carpeta seleccionada no contiene archivos.');
         }

    } catch (err: any) {
         if (err instanceof DOMException && err.name === 'AbortError') { console.log('Selección cancelada.'); }
         else { showError(`Error al seleccionar carpeta: ${err.message || err}`); console.error('Error selecting folder:', err); }
    }
    checkEnableEncryptButton(); // Check if button should be enabled
});

form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (encryptButton.disabled) return; // Prevent submission if already disabled

    // Basic check before starting the async process
    if (!isPublicKeyLoaded || !areFilesSelected) {
         showError("Selecciona la llave pública y los archivos primero.");
         return;
    }
     if (selectedFiles.length > 20) {
        showError('No puedes encriptar más de 20 archivos a la vez.');
        return;
    }

    encryptButton.disabled = true; // Disable immediately
    performEncryption(); // Call the main async encryption function
});

resetButton.addEventListener('click', resetUI);

// --- Initial State ---
resetUI(); // Ensure clean state on load

