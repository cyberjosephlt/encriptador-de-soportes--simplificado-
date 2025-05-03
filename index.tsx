
// Declare JSZip loaded from CDN
declare const JSZip: any;

// --- DOM Elements (Encryption Only) ---
const encryptionForm = document.getElementById('encryption-form') as HTMLFormElement;
const publicKeyInput = document.getElementById('public-key-input') as HTMLInputElement;
const publicKeyStatus = document.getElementById('public-key-status') as HTMLParagraphElement;
const selectFolderButton = document.getElementById('select-folder-button') as HTMLButtonElement;
const fileListElement = document.getElementById('file-list') as HTMLUListElement;
const fileCountError = document.getElementById('file-count-error') as HTMLParagraphElement;
const folderStatus = document.getElementById('folder-status') as HTMLParagraphElement;
const encryptButton = document.getElementById('encrypt-button') as HTMLButtonElement;
const statusArea = document.getElementById('status-area') as HTMLDivElement; // Renamed from encrypt-status-area
const statusMessage = document.getElementById('status-message') as HTMLParagraphElement; // Renamed
const errorMessage = document.getElementById('error-message') as HTMLParagraphElement; // Renamed
const warningMessage = document.getElementById('warning-message') as HTMLParagraphElement; // Renamed
const spinner = document.getElementById('spinner') as HTMLDivElement; // Renamed
const resultArea = document.getElementById('result-area') as HTMLDivElement; // Renamed
const downloadLink = document.getElementById('download-link') as HTMLAnchorElement; // Renamed
const resetButton = document.getElementById('reset-button') as HTMLButtonElement; // Renamed

// --- State Variables (Encryption Only) ---
let selectedFiles: File[] = [];
let publicKeyPem: string | null = null;
let isPublicKeyLoaded = false;
let areFilesSelected = false;

// --- Utility Functions ---

function checkEnableEncryptButton() {
    encryptButton.disabled = !(isPublicKeyLoaded && areFilesSelected);
}

// Simplified updateStatus
function updateStatus(
    message: string | null = null,
    options: { showSpinner?: boolean, isError?: boolean, showWarning?: boolean } = {}
) {
    const { showSpinner = false, isError = false, showWarning = false } = options;

    if (!statusArea || !statusMessage || !errorMessage || !spinner || !resultArea) return;

    statusArea.style.display = message || showSpinner ? 'block' : 'none';
    statusMessage.textContent = message && !isError ? message : '';
    statusMessage.style.display = message && !isError ? 'block' : 'none';

    errorMessage.textContent = message && isError ? `Error: ${message}` : '';
    errorMessage.style.display = message && isError ? 'block' : 'none';

    spinner.style.display = showSpinner ? 'block' : 'none';
    if (warningMessage) warningMessage.style.display = showWarning ? 'block' : 'none';

    if ((message || showSpinner) && !isError) { resultArea.style.display = 'none'; }
    if (!message && !showSpinner) { resultArea.style.display = 'none'; }
}

// Simplified showResult
function showResult(data: { downloadUrl: string, zipName?: string }) {
     updateStatus(null); // Clear status
     if (resultArea && downloadLink && encryptButton && encryptionForm) {
         resultArea.style.display = 'block';
         downloadLink.href = data.downloadUrl;
         downloadLink.download = data.zipName || `encrypted_files.zip`;
         encryptButton.disabled = true;
         encryptionForm.style.display = 'none';
     }
}

// Simplified showError
function showError(message: string | null) {
    if (message === null) {
        updateStatus(null); // Clear messages
    } else {
        updateStatus(message, { isError: true });
        console.error(`[ENCRYPT] Error:`, message);
    }
    // Always re-evaluate button state after error change
    checkEnableEncryptButton();
}

// Renamed resetUI
function resetUI() {
    encryptionForm.reset();
    selectedFiles = []; publicKeyPem = null; isPublicKeyLoaded = false; areFilesSelected = false;
    fileListElement.innerHTML = ''; fileCountError.style.display = 'none'; publicKeyStatus.style.display = 'none'; folderStatus.style.display = 'none';
    updateStatus(null); resultArea.style.display = 'none'; encryptButton.disabled = true; encryptionForm.style.display = 'block';
}

// --- Crypto Helper Functions (Only needed for Encryption) ---
function pemToArrayBuffer(pem: string): ArrayBuffer { const p1="-----BEGIN PUBLIC KEY-----",p2="-----END PUBLIC KEY-----"; let b64=pem.trim(); if(!b64.startsWith(p1)||!b64.includes(p2))throw new Error("Formato PEM de llave pública inválido."); b64=b64.substring(p1.length); b64=b64.substring(0,b64.indexOf(p2)).trim(); try{const s=atob(b64),l=s.length,b=new Uint8Array(l);for(let i=0;i<l;i++)b[i]=s.charCodeAt(i);return b.buffer}catch(e){throw new Error("Error decodificando Base64 de llave pública.")} }
async function importRsaPublicKey(pem: string): Promise<CryptoKey> { const b=pemToArrayBuffer(pem); try{return await crypto.subtle.importKey('spki',b,{name:'RSA-OAEP',hash:'SHA-256'},true,['encrypt'])}catch(e){console.error("Error importando llave pública RSA (SHA-256):",e);try{console.warn("Intentando importar llave pública RSA con SHA-1");return await crypto.subtle.importKey('spki',b,{name:'RSA-OAEP',hash:'SHA-1'},true,['encrypt'])}catch(e2){throw new Error(`Fallo al importar llave pública RSA: ${e}/${e2}`)}} }
async function encryptWithAes(data: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> { return await crypto.subtle.encrypt({name:'AES-CBC',iv},key,data); }
async function encryptWithRsa(data: ArrayBuffer, publicKey: CryptoKey): Promise<ArrayBuffer> { return await crypto.subtle.encrypt({name:'RSA-OAEP'},publicKey,data); }

// --- Encryption Process ---
async function performEncryption() {
    if (!publicKeyPem || selectedFiles.length === 0) { showError("Faltan la llave pública o los archivos."); return; }
    encryptButton.disabled = true; // Disable button right away
    updateStatus("Importando llave pública...", { showSpinner: true, showWarning: true }); await new Promise(r => setTimeout(r, 0));
    let rsaPublicKey: CryptoKey;
    try { rsaPublicKey = await importRsaPublicKey(publicKeyPem); }
    catch (e: any) { showError(`Error importando llave pública: ${e.message}`); return; }

    const results: any[] = []; const totalFiles = selectedFiles.length;
    try {
        for (let i = 0; i < totalFiles; i++) {
            const file = selectedFiles[i]; const fileName = file.name;
            updateStatus(`Encriptando: ${fileName} (${i + 1}/${totalFiles})...`, { showSpinner: true, showWarning: true }); await new Promise(r => setTimeout(r, 0));
            const fileBuffer = await file.arrayBuffer(); const parts = fileName.split('.'); const fileExtension = parts.length > 1 ? `.${parts.pop()}` : ''; const extensionBuffer = new TextEncoder().encode(fileExtension); const extensionLengthBuffer = new ArrayBuffer(4); (new DataView(extensionLengthBuffer)).setUint32(0, extensionBuffer.byteLength, false);
            const aesKey = await crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, true, ["encrypt", "decrypt"]); const aesKeyRaw = await crypto.subtle.exportKey("raw", aesKey); const iv = crypto.getRandomValues(new Uint8Array(16)); const encryptedFileContent = await encryptWithAes(fileBuffer, aesKey, iv); const encryptedAesKey = await encryptWithRsa(aesKeyRaw, rsaPublicKey);
            const finalEncryptedFile = (new Uint8Array([...new Uint8Array(extensionLengthBuffer), ...extensionBuffer, ...iv, ...new Uint8Array(encryptedFileContent)])).buffer; const baseName = fileName.substring(0, fileName.length - fileExtension.length); const encFileName = `${baseName}${fileExtension}.enc`; const keyFileName = `${baseName}${fileExtension}.key`;
            results.push({ encFileName: encFileName, keyFileName: keyFileName, encryptedData: finalEncryptedFile, encryptedKey: encryptedAesKey });
        }
    } catch (e: any) { const currentFile = selectedFiles[results.length]?.name || "archivo"; showError(`Error encriptando ${currentFile}: ${e.message}`); return; }

    updateStatus('Creando archivo ZIP...', { showSpinner: true, showWarning: false }); await new Promise(r => setTimeout(r, 0));
    try {
        const zip = new JSZip(); results.forEach(r => { zip.file(r.encFileName, new Uint8Array(r.encryptedData)); zip.file(r.keyFileName, new Uint8Array(r.encryptedKey)); });
        const zipBlob = await zip.generateAsync({ type: "blob" }); const url = URL.createObjectURL(zipBlob);
        showResult({ downloadUrl: url, zipName: "encrypted_files.zip" });
    } catch (e: any) { showError(`Error creando ZIP: ${e.message}`); }
}

// --- Event Listeners (Encryption Only) ---
publicKeyInput.addEventListener('change', async (e) => {
    const t = e.target as HTMLInputElement; isPublicKeyLoaded = false; publicKeyStatus.style.display = "none"; showError(null);
    if (t.files && t.files.length > 0) {
        const file = t.files[0];
        try {
            publicKeyPem = await file.text();
            if (!publicKeyPem || !publicKeyPem.includes("-----BEGIN PUBLIC KEY-----")) throw new Error("Formato de llave pública inválido.");
            isPublicKeyLoaded = true; publicKeyStatus.style.display = "block";
        } catch (e: any) { showError(`Error al leer llave pública: ${e.message}`); publicKeyPem = null; isPublicKeyLoaded = false; }
    }
    checkEnableEncryptButton();
});

selectFolderButton.addEventListener('click', async () => {
    areFilesSelected = false; folderStatus.style.display = "none"; fileListElement.innerHTML = ""; fileCountError.style.display = "none"; showError(null);
    try {
        const e = await (window as any).showDirectoryPicker(); selectedFiles = []; let t = 0;
        for await (const r of e.values()) if ("file" === r.kind) {
            if (t >= 20) { fileCountError.style.display = "block"; showError("Se superó el límite de 20 archivos."); selectedFiles = []; fileListElement.innerHTML = ""; areFilesSelected = false; break; }
            const n = await r.getFile(); selectedFiles.push(n); const o = document.createElement("li"); o.textContent = n.name; fileListElement.appendChild(o); t++;
        }
        if (selectedFiles.length > 0) { areFilesSelected = true; folderStatus.textContent = `${selectedFiles.length} archivo(s) seleccionado(s).`; folderStatus.style.display = "block"; }
        else { showError("La carpeta seleccionada no contiene archivos."); areFilesSelected = false; }
    } catch (e: any) { if (e instanceof DOMException && "AbortError" === e.name) { console.log("Selección cancelada."); } else { showError(`Error al seleccionar carpeta: ${e.message || e}`); console.error("Error selecting folder:", e); } areFilesSelected = false; }
    finally { checkEnableEncryptButton(); }
});

encryptionForm.addEventListener('submit', (e) => {
    e.preventDefault(); if (encryptButton.disabled) return;
    if (!isPublicKeyLoaded || !areFilesSelected) { showError("Selecciona la llave pública y los archivos primero."); return; }
    if (selectedFiles.length > 20) { showError("No puedes encriptar más de 20 archivos a la vez."); return; }
    performEncryption(); // Calls disable button inside
});

resetButton.addEventListener('click', resetUI);

// --- Initial State ---
resetUI(); // Initialize the encrypt UI

