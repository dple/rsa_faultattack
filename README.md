#FA against RSA-CRT

A simulation of the fault attack against RSA signature with Chinese remainder theorem (CRT). A RSA-CRT is an implementation of the RSA signature that speeds up the computation of RSA by four (4) times due to the computations are performed in the smaller size of modulus. 

Fault Analysis or Bellcore attack [1, 2] against RSA-CRT demonstrated that the RSA private key could be recovered with only one faulty signature that is invalid when verifying with the corresponding public key. A fault can be a software or hardware initiate and carrried out during the computation of one modular exponentiation. Details of attack could be found in [1, 2].


#References
[1] D. Boneh, R. DeMillo, and R. Lipton (1997), "On the importance of checking cryptographic protocols for faults", Eurocrypt '97 
[2] Lenstra, A. K. (1996). "Memo on RSA signature generation in the presence of faults".
