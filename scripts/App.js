import React, { useState } from 'react'
import Header from './components/Header';
import CipherSelector from './components/CipherSelector';
import styled from 'styled-components';
const App = () => {
    const [cipherData, setCipherData] = useState(null);
    const [cipherText, setCipherText] = useState('');
    const handleSubmit = () => {
        console.log('Handle submit called');
    }
    return (
        <Wrapper>
            <div className="container mt-4 my-4 main-container">
                <Header />
                <CipherSelector setCipherData={setCipherData} handleSubmit={handleSubmit}/>
            </div>
        </Wrapper>
    )
}

const Wrapper = styled.div`
    .main-container {
        background-color: #e3fff3;
        border: 1px solid #98d9bd;
        border-radius: 5px;
    }
    
`;

export default App