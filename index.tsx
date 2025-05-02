
// Declare JSZip loaded from CDN
declare const JSZip: any;

// --- Type Definitions ---
interface FilePair { baseName: string; encFile: File; keyFile: File; originalExtension?: string; }
interface DecryptionResult { fileName: string; blob: Blob; }

// --- DOM Elements ---
const encryptTabButton = document.getElementById('encrypt-tab-button') as HTMLButtonElement;
const decryptTabButton = document.getElementById('decrypt-tab-button') as HTMLButtonElement;
const encryptTabContent = document.getElementById('encrypt-tab-content') as HTMLDivElement;
const decryptTabContent = document.getElementById('decrypt-tab-content') as HTMLDivElement;
// Encryption Elements...
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
// Decryption Elements...
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
let encryptSelectedFiles: File[] = []; let encryptPublicKeyPem: string | null = null; let encryptIsPublicKeyLoaded = false; let encryptAreFilesSelected = false;
let decryptPrivateKeyPem: string | null = null; let decryptSelectedPairs: FilePair[] = []; let decryptIsPrivateKeyLoaded = false; let decryptArePairsSelected = false;

// --- Utility Functions ---
function checkEnableEncryptButton() { encryptButton.disabled = !(encryptIsPublicKeyLoaded && encryptAreFilesSelected); }
function checkEnableDecryptButton() { decryptButton.disabled = !(decryptIsPrivateKeyLoaded && decryptArePairsSelected); } // Now relies only on flags

function updateStatus(areaId: 'encrypt' | 'decrypt', message: string | null = null, options: { showSpinner?: boolean, isError?: boolean, showWarning?: boolean } = {}){ const { showSpinner = false, isError = false, showWarning = false } = options; const statusArea = document.getElementById(`${areaId}-status-area`); const statusMessage = document.getElementById(`${areaId}-status-message`); const errorMessage = document.getElementById(`${areaId}-error-message`); const warningMessage = document.getElementById(`${areaId}-warning-message`); const spinner = document.getElementById(`${areaId}-spinner`); const resultArea = document.getElementById(`${areaId}-result-area`); if (!statusArea || !statusMessage || !errorMessage || !spinner || !resultArea) return; statusArea.style.display = message || showSpinner ? 'block' : 'none'; statusMessage.textContent = message && !isError ? message : ''; statusMessage.style.display = message && !isError ? 'block' : 'none'; errorMessage.textContent = message && isError ? `Error: ${message}` : ''; errorMessage.style.display = message && isError ? 'block' : 'none'; spinner.style.display = showSpinner ? 'block' : 'none'; if (warningMessage) warningMessage.style.display = showWarning ? 'block' : 'none'; if ((message || showSpinner) && !isError) { resultArea.style.display = 'none'; } if (!message && !showSpinner) { resultArea.style.display = 'none'; } }
function showResult(areaId: 'encrypt' | 'decrypt', data: { downloadUrl: string, zipName?: string }) { updateStatus(areaId, null); const resultArea = document.getElementById(`${areaId}-result-area`); const downloadLink = document.getElementById(`${areaId}-download-link`); const currentForm = areaId === 'encrypt' ? encryptionForm : decryptionForm; const currentButton = areaId === 'encrypt' ? encryptButton : decryptButton; if (resultArea && downloadLink && currentButton && currentForm) { resultArea.style.display = 'block'; (downloadLink as HTMLAnchorElement).href = data.downloadUrl; (downloadLink as HTMLAnchorElement).download = data.zipName || `${areaId}ed_files.zip`; currentButton.disabled = true; currentForm.style.display = 'none'; } }
// Modified showError to not disable button on clear, relies on checkEnable... functions
function showError(areaId: 'encrypt' | 'decrypt', message: string | null) {
    const button = areaId === 'encrypt' ? encryptButton : decryptButton;
    if (message === null) {
        updateStatus(areaId, null); // Clear messages
    } else {
        updateStatus(areaId, message, { isError: true });
        console.error(`[${areaId}] Error:`, message);
    }
    // Always re-evaluate button state after error change
    if (areaId === 'encrypt') checkEnableEncryptButton();
    else checkEnableDecryptButton();
}
function resetEncryptUI() { encryptionForm.reset(); encryptSelectedFiles = []; encryptPublicKeyPem = null; encryptIsPublicKeyLoaded = false; encryptAreFilesSelected = false; fileListElement.innerHTML = ''; fileCountError.style.display = 'none'; publicKeyStatus.style.display = 'none'; folderStatus.style.display = 'none'; updateStatus('encrypt', null); encryptResultArea.style.display = 'none'; encryptButton.disabled = true; encryptionForm.style.display = 'block'; }
function resetDecryptUI() { decryptionForm.reset(); decryptPrivateKeyPem = null; decryptSelectedPairs = []; decryptIsPrivateKeyLoaded = false; decryptArePairsSelected = false; decryptFileListElement.innerHTML = ''; decryptFileCountError.style.display = 'none'; decryptPrivateKeyStatus.style.display = 'none'; decryptFolderStatus.style.display = 'none'; updateStatus('decrypt', null); decryptResultArea.style.display = 'none'; decryptButton.disabled = true; decryptionForm.style.display = 'block'; }

// --- Crypto Helper Functions ---
function pemToArrayBuffer(pem: string): ArrayBuffer { const pemHeader="-----BEGIN PUBLIC KEY-----",pemFooter="-----END PUBLIC KEY-----",pemHeaderPrivate="-----BEGIN PRIVATE KEY-----",pemFooterPrivate="-----END PRIVATE KEY-----",pemHeaderPrivateRSA="-----BEGIN RSA PRIVATE KEY-----",pemFooterPrivateRSA="-----END RSA PRIVATE KEY-----"; let base64String=pem.trim(); if(base64String.startsWith(pemHeader)){base64String=base64String.substring(pemHeader.length);base64String=base64String.substring(0,base64String.indexOf(pemFooter)).trim();}else if(base64String.startsWith(pemHeaderPrivate)){base64String=base64String.substring(pemHeaderPrivate.length);base64String=base64String.substring(0,base64String.indexOf(pemFooterPrivate)).trim();}else if(base64String.startsWith(pemHeaderPrivateRSA)){base64String=base64String.substring(pemHeaderPrivateRSA.length);base64String=base64String.substring(0,base64String.indexOf(pemFooterPrivateRSA)).trim();}else{throw new Error("Formato PEM no reconocido o inválido (No se encontraron encabezados BEGIN/END).");} try{const binaryString=atob(base64String);const len=binaryString.length;const bytes=new Uint8Array(len);for(let i=0;i<len;i++){bytes[i]=binaryString.charCodeAt(i);}return bytes.buffer;}catch(e){console.error("Error decoding Base64:",e);throw new Error("Error al decodificar la llave PEM (Base64 inválido).");} }
async function importRsaPublicKey(pem: string): Promise<CryptoKey> { const buffer=pemToArrayBuffer(pem); try{return await crypto.subtle.importKey('spki',buffer,{name:'RSA-OAEP',hash:'SHA-256'},true,['encrypt']);}catch(e){console.error("Error importing RSA public key (SHA-256):",e);try{console.warn("Intentando importar llave pública RSA con SHA-1");return await crypto.subtle.importKey('spki',buffer,{name:'RSA-OAEP',hash:'SHA-1'},true,['encrypt']);}catch(e2){console.error("Error importing RSA public key (SHA-1):",e2);throw new Error(`Fallo al importar llave pública RSA: ${e} / ${e2}`);}} }
async function importRsaPrivateKey(pem: string): Promise<CryptoKey> { const buffer = pemToArrayBuffer(pem); try { return await crypto.subtle.importKey('pkcs8', buffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']); } catch (e) { console.error("Error importing RSA private key as PKCS#8 (SHA-256):", e); throw new Error(`Fallo al importar llave privada RSA. Asegúrate de que no esté encriptada y esté en formato PKCS#8 ('-----BEGIN PRIVATE KEY-----'). Error original: ${e}`); } }
async function encryptWithAes(data: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> { return await crypto.subtle.encrypt({name:'AES-CBC',iv},key,data); }
async function decryptWithAes(data: ArrayBuffer, key: CryptoKey, iv: Uint8Array): Promise<ArrayBuffer> { try{return await crypto.subtle.decrypt({name:'AES-CBC',iv},key,data);}catch(e){console.error("AES Decryption failed:",e);throw new Error("Fallo la desencriptación AES. ¿La llave o el IV son correctos?");} }
async function encryptWithRsa(data: ArrayBuffer, publicKey: CryptoKey): Promise<ArrayBuffer> { return await crypto.subtle.encrypt({name:'RSA-OAEP'},publicKey,data); }
async function decryptWithRsa(data: ArrayBuffer, privateKey: CryptoKey): Promise<ArrayBuffer> { try{return await crypto.subtle.decrypt({name:'RSA-OAEP'},privateKey,data);}catch(e){console.error("RSA Decryption failed:",e);throw new Error("Fallo la desencriptación RSA. ¿La llave privada es correcta y corresponde a la pública usada para encriptar?");} }

// --- Encryption Process (No changes) ---
async function performEncryption() { if(!encryptPublicKeyPem||encryptSelectedFiles.length===0){showError("encrypt","Faltan la llave pública o los archivos.");return}encryptButton.disabled=!0;updateStatus("encrypt","Importando llave pública...",{showSpinner:!0,showWarning:!0});await new Promise(e=>setTimeout(e,0));let rsaPublicKey:CryptoKey;try{rsaPublicKey=await importRsaPublicKey(encryptPublicKeyPem)}catch(e:any){showError("encrypt",`Error importando llave pública: ${e.message}`);return}const results:any[]=[];const totalFiles=encryptSelectedFiles.length;try{for(let i=0;i<totalFiles;i++){const file=encryptSelectedFiles[i],fileName=file.name;updateStatus("encrypt",`Encriptando: ${fileName} (${i+1}/${totalFiles})...`,{showSpinner:!0,showWarning:!0});await new Promise(e=>setTimeout(e,0));const fileBuffer=await file.arrayBuffer(),parts=fileName.split("."),fileExtension=parts.length>1?"."+parts.pop():"",extensionBuffer=(new TextEncoder).encode(fileExtension),extensionLengthBuffer=new ArrayBuffer(4);(new DataView(extensionLengthBuffer)).setUint32(0,extensionBuffer.byteLength,!1);const aesKey=await crypto.subtle.generateKey({name:"AES-CBC",length:256},!0,["encrypt","decrypt"]),aesKeyRaw=await crypto.subtle.exportKey("raw",aesKey),iv=crypto.getRandomValues(new Uint8Array(16)),encryptedFileContent=await encryptWithAes(fileBuffer,aesKey,iv),encryptedAesKey=await encryptWithRsa(aesKeyRaw,rsaPublicKey),finalEncryptedFile=(new Uint8Array([...new Uint8Array(extensionLengthBuffer),...extensionBuffer,...iv,...new Uint8Array(encryptedFileContent)])).buffer,baseName=fileName.substring(0,fileName.length-fileExtension.length),encFileName=`${baseName}${fileExtension}.enc`,keyFileName=`${baseName}${fileExtension}.key`;results.push({encFileName:encFileName,keyFileName:keyFileName,encryptedData:finalEncryptedFile,encryptedKey:encryptedAesKey})}}catch(e:any){const t=encryptSelectedFiles[results.length]?.name||"archivo";showError("encrypt",`Error encriptando ${t}: ${e.message}`);return}updateStatus("encrypt","Creando archivo ZIP...",{showSpinner:!0,showWarning:!1});await new Promise(e=>setTimeout(e,0));try{const zip=new JSZip;results.forEach(e=>{zip.file(e.encFileName,new Uint8Array(e.encryptedData)),zip.file(e.keyFileName,new Uint8Array(e.encryptedKey))});const zipBlob=await zip.generateAsync({type:"blob"}),url=URL.createObjectURL(zipBlob);showResult("encrypt",{downloadUrl:url,zipName:"encrypted_files.zip"})}catch(e:any){showError("encrypt",`Error creando ZIP: ${e.message}`)} }

// --- Decryption Process (Import Key moved back here) ---
async function performDecryption() {
    if (!decryptPrivateKeyPem || !decryptArePairsSelected || decryptSelectedPairs.length === 0) {
        showError("decrypt", "Faltan la llave privada o los pares de archivos .enc/.key.");
        return;
    }
    // Disable button explicitly here before async actions
    decryptButton.disabled = true;
    updateStatus("decrypt", "Importando llave privada...", { showSpinner: true, showWarning: true });
    await new Promise(resolve => setTimeout(resolve, 0));

    let rsaPrivateKey: CryptoKey;
    try {
        // !! Key Import moved back here !!
        rsaPrivateKey = await importRsaPrivateKey(decryptPrivateKeyPem);
    } catch (error: any) {
        // If import fails here, show error and stop
        showError("decrypt", `Error importando llave privada: ${error.message}`);
        // No need to return, showError re-evaluates button state
        return;
    }

    const results: DecryptionResult[] = [];
    const totalPairs = decryptSelectedPairs.length;

    try { // Wrap file loop in try/catch
        for (let i = 0; i < totalPairs; i++) {
            const pair = decryptSelectedPairs[i];
            updateStatus("decrypt", `Desencriptando: ${pair.baseName} (${i + 1}/${totalPairs})...`, { showSpinner: true, showWarning: true });
            await new Promise(resolve => setTimeout(resolve, 0));

            const encryptedAesKeyBuffer = await pair.keyFile.arrayBuffer();
            const decryptedAesKeyRaw = await decryptWithRsa(encryptedAesKeyBuffer, rsaPrivateKey);
            const aesKey = await crypto.subtle.importKey('raw', decryptedAesKeyRaw, { name: 'AES-CBC', length: 256 }, true, ['decrypt']);
            const encFileBuffer = await pair.encFile.arrayBuffer();

            if (encFileBuffer.byteLength < 20) throw new Error(`Archivo .enc inválido: ${pair.encFile.name}`);
            const view = new DataView(encFileBuffer); const extensionLength = view.getUint32(0, false);
            if (extensionLength < 0 || extensionLength > 50 || encFileBuffer.byteLength < 4 + extensionLength + 16) throw new Error(`Longitud/formato de extensión inválido en: ${pair.encFile.name}`);

            const extensionBytes = new Uint8Array(encFileBuffer, 4, extensionLength); const originalExtension = new TextDecoder().decode(extensionBytes); pair.originalExtension = originalExtension;
            const iv = new Uint8Array(encFileBuffer, 4 + extensionLength, 16); const encryptedData = encFileBuffer.slice(4 + extensionLength + 16);
            const decryptedData = await decryptWithAes(encryptedData, aesKey, iv);
            const blob = new Blob([decryptedData]);
            let cleanBaseName = pair.baseName; if (cleanBaseName.toLowerCase().endsWith(originalExtension.toLowerCase())) { cleanBaseName = cleanBaseName.substring(0, cleanBaseName.length - originalExtension.length); }
            const finalFileName = cleanBaseName + originalExtension;
            results.push({ fileName: finalFileName, blob: blob });
        }
    } catch (error: any) {
        const currentPairName = decryptSelectedPairs[results.length]?.baseName || 'archivo desconocido';
        showError("decrypt", `Error desencriptando ${currentPairName}: ${error.message}`);
        // Don't return here, let it proceed to ZIP creation if some files succeeded?
        // Or return to stop immediately? Let's stop immediately for simplicity.
        return;
    }

    // --- Create and Download Zip ---
    if (results.length === 0) { showError("decrypt", "No se pudo desencriptar ningún archivo."); return; } // Check needed if loop allows continuing on error
    updateStatus("decrypt", 'Creando archivo ZIP con archivos desencriptados...', { showSpinner: true, showWarning: false });
    await new Promise(resolve => setTimeout(resolve, 0));
    try {
        const zip = new JSZip(); results.forEach(result => { zip.file(result.fileName, result.blob); });
        const zipBlob = await zip.generateAsync({ type: 'blob' }); const url = URL.createObjectURL(zipBlob);
        showResult("decrypt", { downloadUrl: url, zipName: 'decrypted_files.zip' });
    } catch (zipError: any) { showError("decrypt", `Error al crear el archivo ZIP: ${zipError.message}`); }
}


// --- Event Listeners ---
// Tab Switching
encryptTabButton.addEventListener('click',()=>{encryptTabButton.classList.add('active');decryptTabButton.classList.remove('active');encryptTabContent.classList.add('active');decryptTabContent.classList.remove('active');resetDecryptUI();});
decryptTabButton.addEventListener('click',()=>{decryptTabButton.classList.add('active');encryptTabButton.classList.remove('active');decryptTabContent.classList.add('active');encryptTabContent.classList.remove('active');resetEncryptUI();});
// Encryption Listeners
publicKeyInput.addEventListener('change',async(e)=>{const t=e.target as HTMLInputElement;encryptIsPublicKeyLoaded=!1,publicKeyStatus.style.display="none",showError("encrypt",null),t.files&&t.files.length>0&&await async function(){const e=t.files[0];try{encryptPublicKeyPem=await e.text();if(!encryptPublicKeyPem.includes("-----BEGIN PUBLIC KEY-----"))throw new Error("Formato de llave pública inválido.");encryptIsPublicKeyLoaded=!0,publicKeyStatus.style.display="block"}catch(e:any){showError("encrypt",`Error al leer llave pública: ${e.message}`),encryptPublicKeyPem=null}}();checkEnableEncryptButton()});
selectFolderButton.addEventListener('click',async()=>{encryptAreFilesSelected=!1,folderStatus.style.display="none",fileListElement.innerHTML="",fileCountError.style.display="none",showError("encrypt",null);try{const e=await(window as any).showDirectoryPicker();encryptSelectedFiles=[];let t=0;for await(const r of e.values())if("file"===r.kind){if(t>=20){fileCountError.style.display="block",showError("encrypt","Se superó el límite de 20 archivos."),encryptSelectedFiles=[],fileListElement.innerHTML="",encryptAreFilesSelected=!1;break}const n=await r.getFile();encryptSelectedFiles.push(n);const o=document.createElement("li");o.textContent=n.name,fileListElement.appendChild(o),t++}encryptSelectedFiles.length>0?(encryptAreFilesSelected=!0,folderStatus.textContent=`${encryptSelectedFiles.length} archivo(s) seleccionado(s).`,folderStatus.style.display="block"):showError("encrypt","La carpeta seleccionada no contiene archivos.")}catch(e:any){e instanceof DOMException&&"AbortError"===e.name?console.log("Selección cancelada."):(showError("encrypt",`Error al seleccionar carpeta: ${e.message||e}`),console.error("Error selecting folder:",e)),encryptAreFilesSelected=!1}finally{checkEnableEncryptButton()}});
encryptionForm.addEventListener('submit',(e)=>{e.preventDefault();if(encryptButton.disabled)return;if(!encryptIsPublicKeyLoaded||!encryptAreFilesSelected){showError("encrypt","Selecciona la llave pública y los archivos primero.");return}if(encryptSelectedFiles.length>20){showError("encrypt","No puedes encriptar más de 20 archivos a la vez.");return}encryptButton.disabled=!0,performEncryption()});
encryptResetButton.addEventListener('click', resetEncryptUI);

// Decryption Listeners (Reverted Private Key Validation Timing)
decryptPrivateKeyInput.addEventListener('change', async (event) => {
     const input = event.target as HTMLInputElement;
     decryptIsPrivateKeyLoaded = false; // Reset flag
     decryptPrivateKeyStatus.style.display = 'none';
     showError('decrypt', null); // Clear previous errors

    if (input.files && input.files.length > 0) {
        const file = input.files[0];
        try {
            // !! ONLY READ TEXT, DO NOT IMPORT YET !!
            decryptPrivateKeyPem = await file.text();
            // Basic check for presence of headers (less strict than import)
             if (!decryptPrivateKeyPem || !decryptPrivateKeyPem.includes('-----BEGIN') || !decryptPrivateKeyPem.includes('PRIVATE KEY-----')) {
                throw new Error("Archivo no parece ser una llave privada PEM válida.");
             }
            // Assume readable, set flag. Format check deferred to performDecryption.
            decryptIsPrivateKeyLoaded = true;
            decryptPrivateKeyStatus.style.display = 'block';

        } catch (error: any) {
             showError('decrypt', `Error al leer archivo de llave privada: ${error.message}`);
             decryptPrivateKeyPem = null;
             decryptIsPrivateKeyLoaded = false; // Ensure flag is false on error
         }
    }
    // Enable button based ONLY on flags now
    checkEnableDecryptButton();
});

selectDecryptFolderButton.addEventListener('click', async () => {
    decryptArePairsSelected = false; decryptFolderStatus.style.display = 'none'; decryptFileListElement.innerHTML = ''; decryptFileCountError.style.display = 'none'; decryptSelectedPairs = [];
    showError('decrypt', null); updateStatus('decrypt',"Buscando pares .enc/.key...", {showSpinner: true});
    try {
        const dirHandle = await (window as any).showDirectoryPicker(); const fileMap = new Map<string, { encFile?: File, keyFile?: File }>(); let processedFileCount = 0;
        await new Promise(r => setTimeout(r, 0));
        for await (const entry of dirHandle.values()) { if (entry.kind === 'file') { const file = await entry.getFile(); const name = file.name; processedFileCount++; let baseName = name; let isEnc = false; let isKey = false; if (name.toLowerCase().endsWith('.enc')) { baseName = name.substring(0, name.length - 4); isEnc = true; } else if (name.toLowerCase().endsWith('.key')) { baseName = name.substring(0, name.length - 4); isKey = true; } else { continue; } const existing = fileMap.get(baseName) || {}; if (isEnc) existing.encFile = file; if (isKey) existing.keyFile = file; fileMap.set(baseName, existing); } }
        for (const [baseName, files] of fileMap.entries()) { if (files.encFile && files.keyFile) { if (decryptSelectedPairs.length < 20) { decryptSelectedPairs.push({ baseName, encFile: files.encFile, keyFile: files.keyFile }); const listItem = document.createElement('li'); listItem.textContent = `${baseName} (.enc + .key)`; decryptFileListElement.appendChild(listItem); } else { decryptFileCountError.style.display = 'block'; updateStatus('decrypt', 'Se encontraron más de 20 pares, solo se procesarán los primeros 20.', { isError: false }); break; } } }
        if (decryptSelectedPairs.length > 0) { decryptArePairsSelected = true; decryptFolderStatus.textContent = `${decryptSelectedPairs.length} par(es) de archivos encontrado(s).`; decryptFolderStatus.style.display = 'block'; updateStatus('decrypt', null); } // Clear spinner on success
        else { showError('decrypt', `No se encontraron pares .enc/.key válidos en ${processedFileCount} archivos procesados.`); decryptArePairsSelected = false; } // Show error, hide spinner implicitly via showError->updateStatus
    } catch (err: any) { if (err instanceof DOMException && err.name === 'AbortError') { console.log('Selección cancelada.'); updateStatus('decrypt', null); } else { showError('decrypt', `Error al seleccionar carpeta: ${err.message || err}`); console.error('Error selecting folder:', err); } decryptArePairsSelected = false; }
    finally { checkEnableDecryptButton(); } // Check button state after all operations
});

decryptionForm.addEventListener('submit',(e)=>{e.preventDefault();if(decryptButton.disabled)return;if(!decryptIsPrivateKeyLoaded||!decryptArePairsSelected){showError("decrypt","Selecciona la llave privada y una carpeta con pares .enc/.key.");return}decryptButton.disabled=!0,performDecryption()}); // Import happens inside performDecryption now
decryptResetButton.addEventListener('click', resetDecryptUI);

// --- Initial State ---
encryptTabButton.classList.add('active'); encryptTabContent.classList.add('active');
decryptTabButton.classList.remove('active'); decryptTabContent.classList.remove('active');
resetEncryptUI(); resetDecryptUI();

