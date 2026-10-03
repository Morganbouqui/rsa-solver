# RSA Solver

A small educational command-line helper for RSA/CTF exercises involving deliberately weak RSA keys.

It can:

- solve from `n, e, c` when the modulus is weak enough for its bounded local factoring methods;
- solve immediately from known `p, q, e, c`;
- derive `phi(n)` and the private exponent `d`;
- decrypt `c^d mod n`;
- show plaintext as integer, hex, bytes, and UTF-8 text when possible;
- recognize and remove a valid RSAES-PKCS1-v1_5 encryption block;
- inspect RSA values without pretending that ordinary strong RSA is practically factorable;
- cancel cleanly instead of leaving an unbounded SymPy factorization running.

## Install on Ubuntu

Clone the repository:

```bash
git clone https://github.com/Morganbouqui/rsa-solver.git ~/pentest/rsa-solver
cd ~/pentest/rsa-solver
```

Optional but recommended for the final bounded factoring fallback:

```bash
sudo apt update
sudo apt install python3-sympy
```

Install the command globally for your user workflow:

```bash
chmod +x rsa-solver
sudo ln -sf "$HOME/pentest/rsa-solver/rsa-solver" /usr/local/bin/rsa-solver
hash -r
```

Then:

```bash
rsa-solver
```

## Interactive workflow

```text
=== RSA CHALLENGE SOLVER ===

[1] Solve from n, e, c
[2] Solve from p, q, e, c
[3] Inspect RSA values
[0] Exit
```

### 1. Solve from n, e, c

The solver uses bounded local methods in this order:

1. small-prime trial division;
2. Fermat factorization (useful for unusually close primes);
3. Pollard rho;
4. optional SymPy `factorint` in a separate process with a timeout.

If none succeeds, the tool stops cleanly. Failure within these bounds does **not** prove that `n` cannot be factored.

### 2. Solve from p, q, e, c

Use this when a challenge gives the factors or when you obtained them with a dedicated factoring tool. The solver validates the values, derives the private exponent, decrypts the ciphertext, and converts the result.

### 3. Inspect

Displays modulus size and basic structural information. Inspection does not launch factoring.

## Non-interactive usage

```bash
rsa-solver solve --n 3233 --e 17 --c 2790
rsa-solver solve-pq --p 61 --q 53 --e 17 --c 2790
rsa-solver inspect --n 3233 --e 17 --c 2790
```

For `solve`, the optional SymPy fallback defaults to 20 seconds:

```bash
rsa-solver --sympy-timeout 60 solve --n ... --e 65537 --c ...
```

## TryHackMe exercise

For the exercise values:

```text
n = 43941819371451617899582143885098799360907134939870946637129466519309346255747
e = 65537
c = 9002431156311360251224219512084136121048022631163334079215596223698721862766
```

run `rsa-solver`, choose option 1, and enter the values. The bounded factor methods may or may not recover the factors on a given machine. If the exercise supplies `p` and `q` after demonstrating factorization, option 2 completes the RSA recovery immediately.

This is intentional: a general-purpose tool should not imply that arbitrary modern RSA moduli can be cheaply factored.

## Tests

No third-party test framework is required:

```bash
python3 -m unittest discover -s tests -v
```

The unit tests use small fixtures and do not perform expensive factorization.

## Scope

This project is intended for cryptography education, CTFs, and authorized security labs. It is not a replacement for dedicated number-field-sieve factoring software.
