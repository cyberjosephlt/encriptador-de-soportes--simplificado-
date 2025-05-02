
// Declare JSZip loaded from CDN
declare const JSZip: any;

// --- Type Definitions ---
interface FilePair {
    baseName: string;
    encFile: File;
    keyFile: File;
    originalExtension?: string;
}

interface DecryptionResult {
    fileName: string;
    blob: Blob;
}

// --- DOM Elements ---
const encryptTabButton = document.getElementById('encrypt-tab-button') as HTMLButtonElement;
const decryptTabButton = document.getElementById('decrypt-tab-button') as HTMLButtonElement;
const encryptTabContent = document.getElementById('encrypt-tab-content') as HTMLDivElement;
const decryptTabContent = document.getElementById('decrypt-tab-content') as HTMLDivElement;

// Encryption Elements
const encryptionForm = document.getElementById('encryption-form') as HTMLFormElement;
const publicKeyInput = document.getElementById('public-key-input') as HTMLInputElement;
const publicKeyStatus = document.getElementById('public-key-status') as HTMLParagraphElement;
const selectFolderButton = document.getElementById('select-folder-button') as HTMLButtonElement;
const fileListElement = document.getElementById('file-list') as HTMLUListElement;
const fileCountError = document.getElementById('file-count-error') as HTMLParagraphElement;
const folderStatus = document.getElementById('folder-status') as HTMLParagraphElement;
const encryptButton = document.getElementById('encrypt-button') as HTMLButtonElement;
const encryptStatusArea = document.getElementById('encrypt-status-area') as HTMLDivElement;
const encryptStatusMessage = document.getElementById('encrypt-status-message') as HTMLParagraphElement;
const encryptErrorMessage = document.getElementById('encrypt-error-message') as HTMLParagraphElement;
const encryptWarningMessage = document.getElementById('encrypt-warning-message') as HTMLParagraphElement;
const encryptSpinner = document.getElementById('encrypt-spinner') as HTMLDivElement;
const encryptResultArea = document.getElementById('encrypt-result-area') as HTMLDivElement;
const encryptDownloadLink = document.getElementById('encrypt-download-link') as HTMLAnchorElement;
const encryptResetButton = document.getElementById('encrypt-reset-button') as HTMLButtonElement;

// Decryption Elements
const decryptionForm = document.getElementById('decryption-form') as HTMLFormElement;
const decryptPrivateKeyInput = document.getElementById('decrypt-private-key-input') as HTMLInputElement;
const decryptPrivateKeyStatus = document.getElementById('decrypt-private-key-status') as HTMLParagraphElement;
const selectDecryptFolderButton = document.getElementById('select-decrypt-folder-button') as HTMLButtonElement;
const decryptFileListElement = document.getElementById('decrypt-file-list') as HTMLUListElement;
const decryptFileCountError = document.getElementById('decrypt-file-count-error') as HTMLParagraphElement;
const decryptFolderStatus = document.getElementById('decrypt-folder-status') as HTMLParagraphElement;
const decryptButton = document.getElementById('decrypt-button') as HTMLButtonElement;
const decryptStatusArea = document.getElementById('decrypt-status-area') as HTMLDivElement;
const decryptStatusMessage = document.getElementById('decrypt-status-message') as HTMLParagraphElement;
const decryptErrorMessage = document.getElementById('decrypt-error-message') as HTMLParagraphElement;
const decryptWarningMessage = document.getElementById('decrypt-warning-message') as HTMLParagraphElement;
const decryptSpinner = document.getElementById('decrypt-spinner') as HTMLDivElement;
const decryptResultArea = document.getElementById('decrypt-result-area') as HTMLDivElement;
const decryptDownloadLink = document.getElementById('decrypt-download-link') as HTMLAnchorElement;
const decryptResetButton = document.getElementById('decrypt-reset-button') as HTMLButtonElement;

// --- State Variables ---
let encryptSelectedFiles: File[] = [];
let encryptPublicKeyPem: string | null = null;
let encryptIsPublicKeyLoaded = false;
let encryptAreFilesSelected = false;
let decryptPrivateKeyPem: string | null = null;
let decryptSelectedPairs: FilePair[] = [];
let decryptIsPrivateKeyLoaded = false;
let decryptArePairsSelected = false;

// --- Utility Functions ---

function checkEnableEncryptButton() {
    encryptButton.disabled = !(encryptIsPublicKeyLoaded && encryptAreFilesSelected);
}

function checkEnableDecryptButton() {
     decryptButton.disabled = !(decryptIsPrivateKeyLoaded && decryptArePairsSelected);
}

// CORRECTED updateStatus: Doesn't disable button just for showing messages
function updateStatus(
    areaId: 'encrypt' | 'decrypt',
    message: string | null = null,
    options: { showSpinner?: boolean, isError?: boolean, showWarning?: boolean } = {}
) {
    const { showSpinner = false, isError = false, showWarning = false } = options;
    const statusArea = document.getElementById(`${areaId}-status-area`);
    const statusMessage = document.getElementById(`${areaId}-status-message`);
    const errorMessage = document.getElementById(`${areaId}-error-message`);
    const warningMessage = document.getElementById(`${areaId}-warning-message`);
    const spinner = document.getElementById(`${areaId}-spinner`);
    const resultArea = document.getElementById(`${areaId}-result-area`);
    // We don't get the button here anymore, its state is managed separately

    if (!statusArea || !statusMessage || !errorMessage || !spinner || !resultArea) return;

    statusArea.style.display = message || showSpinner ? 'block' : 'none';
    statusMessage.textContent = message && !isError ? message : '';
    statusMessage.style.display = message && !isError ? 'block' : 'none';

    errorMessage.textContent = message && isError ? `Error: ${message}` : '';
    errorMessage.style.display = message && isError ? 'block' : 'none';

    spinner.style.display = showSpinner ? 'block' : 'none';
    if (warningMessage) warningMessage.style.display = showWarning ? 'block' : 'none';

    // Hide results area if showing status/spinner (unless it's an error state, then results might still be relevant if shown before)
    if ((message || showSpinner) && !isError) {
         resultArea.style.display = 'none';
    }
     // If clearing status, also clear result area
    if (!message && !showSpinner) {
         resultArea.style.display = 'none';
    }
}


function showResult(areaId: 'encrypt' | 'decrypt', data: { downloadUrl: string, zipName?: string }) {
     updateStatus(areaId, null); // Clear status area completely
     const resultArea = document.getElementById(`${areaId}-result-area`);
     const downloadLink = document.getElementById(`${areaId}-download-link`);
     const currentForm = areaId === 'encrypt' ? encryptionForm : decryptionForm;
     const currentButton = areaId === 'encrypt' ? encryptButton : decryptButton;

     if (resultArea && downloadLink && currentButton && currentForm) {
         resultArea.style.display = 'block';
         (downloadLink as HTMLAnchorElement).href = data.downloadUrl;
         (downloadLink as HTMLAnchorElement).download = data.zipName || `${areaId}ed_files.zip`;
         currentButton.disabled = true; // Button is disabled AFTER showing results
         currentForm.style.display = 'none';
     }
}

function showError(areaId: 'encrypt' | 'decrypt', message: string | null) {
    const button = areaId === 'encrypt' ? encryptButton : decryptButton;
    if (message === null) { // Clear error state
         updateStatus(areaId, null); // Clear messages
         // Re-check button state after clearing error
         if (areaId === 'encrypt') checkEnableEncryptButton();
         else checkEnableDecryptButton();
    } else {
         updateStatus(areaId, message, { isError: true });
         button.disabled = false; // Ensure button is enabled on error display
          // Re-check prerequisites, might still be disabled if inputs are missing
         if (areaId === 'encrypt') checkEnableEncryptButton();
         else checkEnableDecryptButton();
         console.error(`[${areaId}] Error:`, message);
    }
}


function resetEncryptUI() {
    encryptionForm.reset();
    encryptSelectedFiles = []; encryptPublicKeyPem = null; encryptIsPublicKeyLoaded = false; encryptAreFilesSelected = false;
    fileListElement.innerHTML = ''; fileCountError.style.display = 'none'; publicKeyStatus.style.display = 'none'; folderStatus.style.display = 'none';
    updateStatus('encrypt', null); encryptResultArea.style.display = 'none'; encryptButton.disabled = true; encryptionForm.style.display = 'block';
}

function resetDecryptUI() {
    decryptionForm.reset();
    decryptPrivateKeyPem = null; decryptSelectedPairs = []; decryptIsPrivateKeyLoaded = false; decryptArePairsSelected = false;
    decryptFileListElement.innerHTML = ''; decryptFileCountError.style.display = 'none'; decryptPrivateKeyStatus.style.display = 'none'; decryptFolderStatus.style.display = 'none';
    updateStatus('decrypt', null); decryptResultArea.style.display = 'none'; decryptButton.disabled = true; decryptionForm.style.display = 'block';
}

// --- Crypto Helper Functions (No changes) ---
function pemToArrayBuffer(pem: string): ArrayBuffer { const pemHeader="-----BEGIN PUBLIC KEY-----",pemFooter="-----END PUBLIC KEY-----",pemHeaderPrivate="-----BEGIN PRIVATE KEY-----",pemFooterPrivate="-----END PRIVATE KEY-----",pemHeaderPrivateRSA="-----BEGIN RSA PRIVATE KEY-----",pemFooterPrivateRSA="-----END RSA PRIVATE KEY-----"; let base64String=pem.trim(); if(base64String.startsWith(pemHeader)){base64String=base64String.substring(pemHeader.length);base64String=base64String.substring(0,base64String.indexOf(pemFooter)).trim();}else if(base64String.startsWith(pemHeaderPrivate)){base64String=base64String.substring(pemHeaderPrivate.length);base64String=base64String.substring(0,base64String.indexOf(pemFooterPrivate)).trim();}else if(base64String.startsWith(pemHeaderPrivateRSA)){base64String=base64String.substring(pemHeaderPrivateRSA.length);base64String=base64String.substring(0,base64String.indexOf(pemFooterPrivateRSA)).trim();}else{throw new Error("Formato PEM no reconocido o inválido.");} try{const binaryString=atob(base64String);const len=binaryString.length;const bytes=new Uint8Array(len);for(let i=0;i<len;i++){bytes[i]=binaryString.charCodeAt(i);}return bytes.buffer;}catch(e){console.error("Error decoding Base64:",e);throw new Error("Error al decodificar la llave PEM (Base64 inválido).");} }
async function importRsaPublicKey(pem: string): Promise<CryptoKey> { const buffer=pemToArrayBuffer(pem); try{return await crypto.subtle.importKey('spki',buffer,{name:'RSA-OAEP',hash:'SHA-256'},true,['encrypt']);}catch(e){console.error("Error importing RSA public key (SHA-256):",e);try{console.warn("Intentando importar llave pública RSA con SHA-1");return await crypto.subtle.importKey('spki',buffer,{name:'RSA-OAEP',hash:'SHA-1'},true,['encrypt']);}catch(e2){console.error("Error importing RSA public key (SHA-1):",e2);throw new Error(`Fallo al importar llave pública RSA: ${e} / ${e2}`);}} }
async function importRsaPrivateKey(pem: string): Promise<CryptoKey> { const buffer=pemToArrayBuffer(pem); try{return await crypto.subtle.importKey('pkcs8',buffer,{name:'RSA-OAEP',hash:'SHA-256'},true,['decrypt']);}catch(e){console.error("Error importing RSA private key as PKCS#8 (SHA-256):",e);throw new Error(`Fallo al importar llave privada RSA (se espera formato PKCS#8): ${e}`);} }
async function encryptWithAes(data: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> { return await crypto.subtle.encrypt({name:'AES-CBC',iv},key,data); }
async function decryptWithAes(data: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> { try{return await crypto.subtle.decrypt({name:'AES-CBC',iv},key,data);}catch(e){console.error("AES Decryption failed:",e);throw new Error("Fallo la desencriptación AES. ¿La llave o el IV son correctos?");} }
async function encryptWithRsa(data: ArrayBuffer, publicKey: CryptoKey): Promise<ArrayBuffer> { return await crypto.subtle.encrypt({name:'RSA-OAEP'},publicKey,data); }
async function decryptWithRsa(data: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> { try{return await crypto.subtle.decrypt({name:'RSA-OAEP'},privateKey,data);}catch(e){console.error("RSA Decryption failed:",e);throw new Error("Fallo la desencriptación RSA. ¿La llave privada es correcta y corresponde a la pública usada para encriptar?");} }

// --- Encryption Process (No changes) ---
async function performEncryption() { if(!encryptPublicKeyPem||encryptSelectedFiles.length===0){showError("encrypt","Faltan la llave pública o los archivos.");return}encryptButton.disabled=!0,updateStatus("encrypt","Importando llave pública...",{showSpinner:!0,showWarning:!0});await new Promise(e=>setTimeout(e,0));let rsaPublicKey:CryptoKey;try{rsaPublicKey=await importRsaPublicKey(encryptPublicKeyPem)}catch(e:any){showError("encrypt",`Error importando llave pública: ${e.message}`);return}const results:any[]=[];const totalFiles=encryptSelectedFiles.length;try{for(let i=0;i<totalFiles;i++){const file=encryptSelectedFiles[i],fileName=file.name;updateStatus("encrypt",`Encriptando: ${fileName} (${i+1}/${totalFiles})...`,{showSpinner:!0,showWarning:!0});await new Promise(e=>setTimeout(e,0));const fileBuffer=await file.arrayBuffer(),parts=fileName.split("."),fileExtension=parts.length>1?"."+parts.pop():"",extensionBuffer=(new TextEncoder).encode(fileExtension),extensionLengthBuffer=new ArrayBuffer(4);(new DataView(extensionLengthBuffer)).setUint32(0,extensionBuffer.byteLength,!1);const aesKey=await crypto.subtle.generateKey({name:"AES-CBC",length:256},!0,["encrypt","decrypt"]),aesKeyRaw=await crypto.subtle.exportKey("raw",aesKey),iv=crypto.getRandomValues(new Uint8Array(16)),encryptedFileContent=await encryptWithAes(fileBuffer,aesKey,iv),encryptedAesKey=await encryptWithRsa(aesKeyRaw,rsaPublicKey),finalEncryptedFile=(new Uint8Array([...new Uint8Array(extensionLengthBuffer),...extensionBuffer,...iv,...new Uint8Array(encryptedFileContent)])).buffer,baseName=fileName.substring(0,fileName.length-fileExtension.length),encFileName=`${baseName}${fileExtension}.enc`,keyFileName=`${baseName}${fileExtension}.key`;results.push({encFileName:encFileName,keyFileName:keyFileName,encryptedData:finalEncryptedFile,encryptedKey:encryptedAesKey})}}catch(e:any){const t=encryptSelectedFiles[results.length]?.name||"archivo";showError("encrypt",`Error encriptando ${t}: ${e.message}`);return}updateStatus("encrypt","Creando archivo ZIP...",{showSpinner:!0,showWarning:!1});await new Promise(e=>setTimeout(e,0));try{const zip=new JSZip;results.forEach(e=>{zip.file(e.encFileName,new Uint8Array(e.encryptedData)),zip.file(e.keyFileName,new Uint8Array(e.encryptedKey))});const zipBlob=await zip.generateAsync({type:"blob"}),url=URL.createObjectURL(zipBlob);showResult("encrypt",{downloadUrl:url,zipName:"encrypted_files.zip"})}catch(e:any){showError("encrypt",`Error creando ZIP: ${e.message}`)} }

// --- Decryption Process (No changes needed here, logic remains) ---
async function performDecryption() { if(!decryptPrivateKeyPem||!decryptArePairsSelected||decryptSelectedPairs.length===0){showError("decrypt","Faltan la llave privada o los pares de archivos .enc/.key.");return}decryptButton.disabled=!0,updateStatus("decrypt","Importando llave privada...",{showSpinner:!0,showWarning:!0});await new Promise(e=>setTimeout(e,0));let rsaPrivateKey:CryptoKey;try{rsaPrivateKey=await importRsaPrivateKey(decryptPrivateKeyPem)}catch(e:any){showError("decrypt",`Error importando llave privada: ${e.message}`);return}const results:DecryptionResult[]=[];const totalPairs=decryptSelectedPairs.length;try{for(let i=0;i<totalPairs;i++){const pair=decryptSelectedPairs[i];updateStatus("decrypt",`Desencriptando: ${pair.baseName} (${i+1}/${totalPairs})...`,{showSpinner:!0,showWarning:!0});await new Promise(e=>setTimeout(e,0));const encryptedAesKeyBuffer=await pair.keyFile.arrayBuffer(),decryptedAesKeyRaw=await decryptWithRsa(encryptedAesKeyBuffer,rsaPrivateKey),aesKey=await crypto.subtle.importKey("raw",decryptedAesKeyRaw,{name:"AES-CBC",length:256},!0,["decrypt"]),encFileBuffer=await pair.encFile.arrayBuffer();if(encFileBuffer.byteLength<20)throw new Error(`Archivo .enc inválido: ${pair.encFile.name}`);const view=new DataView(encFileBuffer),extensionLength=view.getUint32(0,!1);if(extensionLength<0||extensionLength>50||encFileBuffer.byteLength<4+extensionLength+16)throw new Error(`Longitud/formato de extensión inválido en: ${pair.encFile.name}`);const extensionBytes=new Uint8Array(encFileBuffer,4,extensionLength),originalExtension=(new TextDecoder).decode(extensionBytes);pair.originalExtension=originalExtension;const iv=new Uint8Array(encFileBuffer,4+extensionLength,16),encryptedData=encFileBuffer.slice(4+extensionLength+16),decryptedData=await decryptWithAes(encryptedData,aesKey,iv),blob=new Blob([decryptedData]);let cleanBaseName=pair.baseName;cleanBaseName.toLowerCase().endsWith(originalExtension.toLowerCase())&&(cleanBaseName=cleanBaseName.substring(0,cleanBaseName.length-originalExtension.length));const finalFileName=cleanBaseName+originalExtension;results.push({fileName:finalFileName,blob:blob})}}catch(e:any){const t=decryptSelectedPairs[results.length]?.baseName||"archivo desconocido";showError("decrypt",`Error desencriptando ${t}: ${e.message}`);return}if(results.length===0){showError("decrypt","No se pudo desencriptar ningún archivo.");return}updateStatus("decrypt","Creando archivo ZIP con archivos desencriptados...",{showSpinner:!0,showWarning:!1});await new Promise(e=>setTimeout(e,0));try{const zip=new JSZip;results.forEach(e=>{zip.file(e.fileName,e.blob)});const zipBlob=await zip.generateAsync({type:"blob"}),url=URL.createObjectURL(zipBlob);showResult("decrypt",{downloadUrl:url,zipName:"decrypted_files.zip"})}catch(e:any){showError("decrypt",`Error al crear el archivo ZIP: ${e.message}`)} }


// --- Event Listeners ---

// Tab Switching
encryptTabButton.addEventListener('click',()=>{encryptTabButton.classList.add('active');decryptTabButton.classList.remove('active');encryptTabContent.classList.add('active');decryptTabContent.classList.remove('active');resetDecryptUI();});
decryptTabButton.addEventListener('click',()=>{decryptTabButton.classList.add('active');encryptTabButton.classList.remove('active');decryptTabContent.classList.add('active');encryptTabContent.classList.remove('active');resetEncryptUI();});

// Encryption Listeners (No changes needed)
publicKeyInput.addEventListener('change',async(e)=>{const t=e.target as HTMLInputElement;encryptIsPublicKeyLoaded=!1,publicKeyStatus.style.display="none",t.files&&t.files.length>0&&await async function(){const e=t.files[0];try{encryptPublicKeyPem=await e.text();if(!encryptPublicKeyPem.includes("-----BEGIN PUBLIC KEY-----"))throw new Error("Formato de llave pública inválido.");encryptIsPublicKeyLoaded=!0,publicKeyStatus.style.display="block",showError("encrypt",null)}catch(e:any){showError("encrypt",`Error al leer llave pública: ${e.message}`),encryptPublicKeyPem=null}}();checkEnableEncryptButton()});
selectFolderButton.addEventListener('click',async()=>{encryptAreFilesSelected=!1,folderStatus.style.display="none",fileListElement.innerHTML="",fileCountError.style.display="none";try{const e=await(window as any).showDirectoryPicker();encryptSelectedFiles=[];let t=0;for await(const r of e.values())if("file"===r.kind){if(t>=20){fileCountError.style.display="block",showError("encrypt","Se superó el límite de 20 archivos."),encryptSelectedFiles=[],fileListElement.innerHTML="",encryptAreFilesSelected=!1,checkEnableEncryptButton();return}const n=await r.getFile();encryptSelectedFiles.push(n);const o=document.createElement("li");o.textContent=n.name,fileListElement.appendChild(o),t++}encryptSelectedFiles.length>0?(encryptAreFilesSelected=!0,folderStatus.textContent=`${encryptSelectedFiles.length} archivo(s) seleccionado(s).`,folderStatus.style.display="block",showError("encrypt",null)):showError("encrypt","La carpeta seleccionada no contiene archivos.")}catch(e:any){e instanceof DOMException&&"AbortError"===e.name?console.log("Selección cancelada."):(showError("encrypt",`Error al seleccionar carpeta: ${e.message||e}`),console.error("Error selecting folder:",e))}checkEnableEncryptButton()});
encryptionForm.addEventListener('submit',(e)=>{e.preventDefault();if(encryptButton.disabled)return;if(!encryptIsPublicKeyLoaded||!encryptAreFilesSelected){showError("encrypt","Selecciona la llave pública y los archivos primero.");return}if(encryptSelectedFiles.length>20){showError("encrypt","No puedes encriptar más de 20 archivos a la vez.");return}encryptButton.disabled=!0,performEncryption()});
encryptResetButton.addEventListener('click', resetEncryptUI);

// Decryption Listeners (Corrected)
decryptPrivateKeyInput.addEventListener('change', async (event) => {
     const input = event.target as HTMLInputElement;
     decryptIsPrivateKeyLoaded = false;
     decryptPrivateKeyStatus.style.display = 'none';
    if (input.files && input.files.length > 0) {
        const file = input.files[0];
        try {
            decryptPrivateKeyPem = await file.text();
             if (!decryptPrivateKeyPem.includes('-----BEGIN') || !decryptPrivateKeyPem.includes('PRIVATE KEY-----')) throw new Error("Formato de llave privada inválido.");
            decryptIsPrivateKeyLoaded = true;
            decryptPrivateKeyStatus.style.display = 'block';
             showError('decrypt', null); // Clear previous errors
        } catch (error: any) { showError('decrypt', `Error al leer llave privada: ${error.message}`); decryptPrivateKeyPem = null; }
    }
    checkEnableDecryptButton(); // Check if button should be enabled
});

selectDecryptFolderButton.addEventListener('click', async () => {
    decryptArePairsSelected = false;
    decryptFolderStatus.style.display = 'none';
    decryptFileListElement.innerHTML = '';
    decryptFileCountError.style.display = 'none';
    decryptSelectedPairs = [];
    updateStatus('decrypt',"Buscando pares .enc/.key...", {showSpinner: true}); // Show spinner while searching

    try {
        // @ts-ignore - Experimental API
        const dirHandle = await window.showDirectoryPicker();
        const fileMap = new Map<string, { encFile?: File, keyFile?: File }>();
        let processedFileCount = 0;

        // Allow UI to show spinner before potentially long loop
        await new Promise(r => setTimeout(r, 0));

        // @ts-ignore - Experimental API
        for await (const entry of dirHandle.values()) {
            if (entry.kind === 'file') {
                 // @ts-ignore - Experimental API
                const file = await entry.getFile();
                const name = file.name;
                processedFileCount++;
                let baseName = name; let isEnc = false; let isKey = false;
                 if (name.toLowerCase().endsWith('.enc')) { baseName = name.substring(0, name.length - 4); isEnc = true; }
                 else if (name.toLowerCase().endsWith('.key')) { baseName = name.substring(0, name.length - 4); isKey = true; }
                 else { continue; } // Skip non-relevant files
                const existing = fileMap.get(baseName) || {};
                if (isEnc) existing.encFile = file;
                if (isKey) existing.keyFile = file;
                fileMap.set(baseName, existing);
            }
        }

        // Identify valid pairs
        for (const [baseName, files] of fileMap.entries()) {
            if (files.encFile && files.keyFile) {
                if (decryptSelectedPairs.length < 20) {
                    decryptSelectedPairs.push({ baseName, encFile: files.encFile, keyFile: files.keyFile });
                    const listItem = document.createElement('li');
                     listItem.textContent = `${baseName} (.enc + .key)`;
                     decryptFileListElement.appendChild(listItem);
                } else {
                    decryptFileCountError.style.display = 'block';
                    // Use updateStatus for consistency, but mark as non-error
                     updateStatus('decrypt', 'Se encontraron más de 20 pares, solo se procesarán los primeros 20.', { isError: false });
                    break;
                }
            }
        }

        if (decryptSelectedPairs.length > 0) {
            decryptArePairsSelected = true;
            decryptFolderStatus.textContent = `${decryptSelectedPairs.length} par(es) de archivos encontrado(s).`;
            decryptFolderStatus.style.display = 'block';
            // Clear status spinner/message if successful
             updateStatus('decrypt', null);
             showError('decrypt', null); // Clear previous errors
        } else {
            // Use showError to display the message without enabling the button yet
             showError('decrypt', `No se encontraron pares .enc/.key válidos en ${processedFileCount} archivos procesados.`);
            decryptArePairsSelected = false; // Explicitly set to false
        }

    } catch (err: any) {
         if (err instanceof DOMException && err.name === 'AbortError') {
             console.log('Selección cancelada.');
             updateStatus('decrypt', null); // Clear spinner on cancel
         } else {
             showError('decrypt', `Error al seleccionar carpeta: ${err.message || err}`);
             console.error('Error selecting folder:', err);
         }
         decryptArePairsSelected = false; // Ensure flag is false on error
    } finally {
         // Check button state AFTER potentially showing errors or success messages
         checkEnableDecryptButton();
          // Ensure spinner is hidden if no other message is showing
         const statusMsg = document.getElementById('decrypt-status-message')?.textContent;
         const errorMsg = document.getElementById('decrypt-error-message')?.textContent;
         if (!statusMsg && !errorMsg) {
             updateStatus('decrypt', null); // Hide spinner if nothing else to show
         }
    }
});

decryptionForm.addEventListener('submit', (event) => {
    event.preventDefault();
    if (decryptButton.disabled) return;
     if (!decryptIsPrivateKeyLoaded || !decryptArePairsSelected) {
        showError("decrypt", "Selecciona la llave privada y una carpeta con pares .enc/.key.");
        return;
     }
    decryptButton.disabled = true; // Disable button before starting async work
    performDecryption();
});

decryptResetButton.addEventListener('click', resetDecryptUI);

// --- Initial State ---
encryptTabButton.classList.add('active'); encryptTabContent.classList.add('active');
decryptTabButton.classList.remove('active'); decryptTabContent.classList.remove('active');
resetEncryptUI(); resetDecryptUI();

