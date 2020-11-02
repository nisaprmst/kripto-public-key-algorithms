import React from 'react'
import styled from 'styled-components';

const Header = () => {
    return (
        <Wrapper>
            <h1>AwoMes Cipher Tools</h1>
            <p>Encryption and Decryption for various public key ciphers</p>
        </Wrapper>
    )
}

const Wrapper = styled.div`
    display: flex;
    flex-direction: column;
    color: #222222;
    padding: 1rem;
`;

export default Header
