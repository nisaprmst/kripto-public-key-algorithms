import React, { useState, useEffect } from 'react'
import styled from 'styled-components'
import { randomPrime, encrypt_rsa, decrypt_RSA, decryptElgamal, encryptElgamal, generate_RSA, generate_elgamal } from "../algorithm";

const CipherSelector = ({setCipherData, handleSubmit}) => {
    const [cipher, setCipher] = useState('elgamal');
    const [textData, setTextData] = useState('');
    const [blobData, setBlobData] = useState(null);
    const [arrBuf, setArrBuf] = useState(null);
    const [isEncryptFile, setIsEncryptFile] = useState(null);
    const [keys, setKeys] = useState(null);

    const handleCipherSelected = (selectEl) => {
        const val = selectEl.options[selectEl.selectedIndex].value;
        setCipher(val);
    };
    useEffect( () => {
        console.log(keys);
    },[keys]) 

    const handleGenerateKeys = () => {
        if (cipher === 'elgamal') {
            setKeys(generate_elgamal());
        } else if (cipher === 'RSA') {
            const p = randomPrime();
            const q = randomPrime();
            setKeys(generate_RSA(p, q));
        }
    }

    const handleFileLoader = (fileNode) => {
        const reader = new FileReader();
        reader.onload = () => {
            document.getElementById('input-text').value = reader.result.byteLength;
            const uint8arr = new Uint8Array(reader.result);
            const standardArr = Array.from(uint8arr);
            const enc = new TextEncoder("utf-8");
            document.getElementById('input-text').value = enc.decode(uint8arr);
            setTextData(enc.decode(uint8arr));            
        }
        reader.readAsArrayBuffer(fileNode.files[0]);
    }
    const handleCipherSubmit = (is_encrypt) => {
        if (is_encrypt) {
            if (cipher === 'elgamal') {
                const ctext = encryptElgamal(keys.public, textData);
                document.getElementById('output-text').innerText = ctext;
            } if (cipher === 'RSA') {
                const ctext = encrypt_rsa(keys.public, textData);
                document.getElementById('output-text').innerText = ctext;
            }
        } else {
            const ctext = document.getElementById('output-text').value;
            if (cipher === 'elgamal') {
                const ptext = decryptElgamal(keys.private, ctext);
                console.log(ptext);
                document.getElementById('input-text').innerText = ptext;
            } else if (cipher === 'RSA') {
                const ptext = decrypt_RSA(keys.private, ctext);
                console.log(ptext);
                document.getElementById('input-text').innerText = ptext;
            }
        }
        
    }

    const handleFileSave = () => {
        const a = document.createElement("a");
        document.body.appendChild(a);
        a.style = 'display: none';
        const blobDataHere = new Blob([blobData], { type: 'octet/stream'});
        a.href = window.URL.createObjectURL(blobDataHere);
        a.download = `${isEncryptFile ? 'encrypted' : 'decrypted'}_data.bin`;
        a.click();
        window.URL.revokeObjectURL(a.href);
        console.log(blobData);
    }
    
    return (
        <Wrapper>
            <p>Cipher Method</p>
            <select name="cipher-selection" id="cipher-selection" onChange={(e) => handleCipherSelected(e.target)}>
                <option value="elgamal">Elgamal</option>
                <option value="RSA">RSA</option>
                <option value="diffie">Diffie-Hellman</option>
            </select>
            <div className="cipher-input">
                {
                    cipher === 'elgamal' ? (
                        <div className="elgamal">
                            <div className="buttons">
                                <span className="gas-button" onClick={() => handleGenerateKeys()}>Generate Elgamal Keys</span>
                            </div>
                        </div>
                    ) : cipher === 'diffie' ? (
                        <div className="diffie">
                            <div className="buttons">
                                <span className="gas-button" onClick={() => handleGenerateKeys()}>Generate Diffie-Hellman Keys</span>
                            </div>
                        </div>
                    ) : cipher === 'RSA' ? (
                        <div className="RSA">
                            <div className="buttons">
                                <span className="gas-button" onClick={() => handleGenerateKeys()}>Generate RSA Keys</span>
                            </div>
                        </div>
                    ) : null
                }
            </div>
            <div>
                
            </div>           
            <div>
            {
                cipher !== 'diffie' ? (
                    <div>
                        <div className="buttons">
                            <span className="gas-button" onClick={() => handleCipherSubmit(true)}>Encrypt</span>
                            <span className="gas-button" onClick={() => handleCipherSubmit(false)}>Decrypt</span>
                        </div>
                        <div className="io-field">
                            <p>Input Text</p>
                            <input type="file" name="file-loader" id="file-loader" onChange={(e) => handleFileLoader(e.target)} />
                            <textarea name="input-text" id="input-text" rows="3" onChange={(e) => setTextData(e.target.value)}></textarea>
                        </div>
                        <div className="io-field">
                            <p>Output Text</p>
                            <span className="gas-button" onClick={() => handleFileSave()}>Save</span>
                            <textarea name="input-text" id="output-text" rows="10"></textarea>
                        </div>
                    </div>
                ) : null
            }
            </div>
        </Wrapper>
    )
}
const Wrapper = styled.div`
    padding-left: 1.5rem;
    display: flex;
    flex-direction: column;
    .io-field {
        margin-top: 1rem;
        textarea {
            width:100%;
        }
    }
    .buttons {
        display: flex;
    }
    p {
        margin-block-end: 0;
        margin-block-start: 0;
    }
    option {
        padding: 5px;
    }
    .cipher-input {
        margin-top: 1rem;
        margin-bottom: 1rem;
    }
    .gas-button {
        padding: 10px;
        padding-top: 5px;
        padding-bottom: 5px;
        min-width: 100px;
        background-color: #1e9c66;
        color: white;
        border: 1px solid #0f6b44;
        border-radius: 5px;
        &--red {
            background-color: #c25d55;
            border: 1px solid #87362f;
        }
    }
    .gas-button:hover {
        cursor: pointer;
        background-color: black;
    }
    .elgamal {
        input[type=radio] {
            margin-right: 5px;
        }
        label {
            margin-right: 2rem;
        }
    }
    
`;
export default CipherSelector
