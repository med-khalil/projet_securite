Projet securité:

A chat application that uses both asymmetric and symmetric encryption. 

First the server and the client generate a public and a private key and exchange them. 
Then the server uses the client public key to encrypt a random generated session key and it will be shared with the client.
Then the client will decrypt it with its own private key and uses the secret to encrypt the messages exchanged between both parties.
![](https://raw.githubusercontent.com/med-khalil/projet_securite/main/demo.gif)
