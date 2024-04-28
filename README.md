implement an client-server application that use brainpoolP256r1 crytographic curve to generate a set set of ECC public/private keys
The keys will be generated a common shared secret key to encrypt and decrypt a plaintext message

## Server
exchange public key through network with client, receive the encrypted text client send and decode
### State Transition Diagram for Client 
<img width="964" alt="image" src="https://github.com/KYang72Bcit/ECC_key_generation_exchange/assets/90719969/e34fdde5-d772-4112-a1b5-d2cd35fbf702">



## Client
exchange public key through network with server, receive user input from console, encrypt it and send to server
### State Transition Diagram for Client 
<img width="985" alt="image" src="https://github.com/KYang72Bcit/ECC_key_generation_exchange/assets/90719969/567ee0e6-9cd8-4b7d-aaa3-3de0fe066869">

