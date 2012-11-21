# naive crypto

A collection of cryptographic primitives, and programs that crack them.

## Motivation

When I took a cryptography course in university, I often came across
statements like: "This scheme is trivially broken if less than 4 encryption
rounds are used" or "An attacker could easily forge authenticated messages if
the initialization vector was chosen at random."

Although I could mathematically prove these statements, I was curious to see
how really "trivial" breaking these schemes was in practice.

> NOTE: This is probably obvious by now, but you should never use any of the
> cryptographic functions here to secure your applications, these are meant
> solely as targets to satisfy the hobbyist cryptanalyst in me (or you!)

## Project Structure

`crypto`:
    Contains the cryptographic functions.

`runners`:
    Contains classes used to run experiments. For example,
    `runners.classical.SubstitutionCipherRunner` can be used to obtain a
    substitution ciphertext using a (unknown to you) random key, from which
    you would then try to recover the plaintext.

`crackers`:
    Contains programs that crack cryptographic schemes.

## References

Most of the material I used for this project come from the lovely
[Introduction to Modern Cryptography][imc] by Katz and Lindell.


[imc]: http://www.cs.umd.edu/~jkatz/imc.html
