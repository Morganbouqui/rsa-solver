import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rsa_solver", ROOT / "rsa-solver")
rsa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rsa)


class RSASolverTests(unittest.TestCase):
    def test_parse_decimal(self):
        self.assertEqual(rsa.parse_int("65537"), 65537)

    def test_parse_hex(self):
        self.assertEqual(rsa.parse_int("0xff"), 255)

    def test_reject_negative(self):
        with self.assertRaises(ValueError):
            rsa.parse_int("-1")

    def test_int_to_bytes(self):
        self.assertEqual(rsa.int_to_bytes(0x6869), b"hi")

    def test_toy_rsa_decrypt(self):
        # Classic toy RSA: p=61, q=53, e=17, m=65, c=2790.
        result = rsa.decrypt_with_factors(61, 53, 17, 2790)
        self.assertEqual(result["n"], 3233)
        self.assertEqual(result["m"], 65)
        self.assertEqual(result["raw"], b"A")

    def test_bad_ciphertext_rejected(self):
        with self.assertRaises(ValueError):
            rsa.decrypt_with_factors(61, 53, 17, 3233)

    def test_noninvertible_e_rejected(self):
        with self.assertRaises(ValueError):
            rsa.decrypt_with_factors(61, 53, 12, 42)

    def test_small_prime_factor(self):
        result = rsa.factor_weak_modulus(101 * 103, sympy_timeout=0)
        self.assertEqual(result.p * result.q, 101 * 103)

    def test_fermat_factor(self):
        result = rsa.fermat_factor(10007 * 10009, max_steps=100)
        self.assertIsNotNone(result)
        self.assertEqual(result.p * result.q, 10007 * 10009)

    def test_pollard_rho(self):
        f = rsa.pollard_rho(8051, attempts=8, iterations=10000)
        self.assertIn(f, (83, 97))

    def test_factor_failure_is_clean(self):
        with mock.patch.object(rsa, "_small_prime_factor", return_value=None), \
             mock.patch.object(rsa, "fermat_factor", return_value=None), \
             mock.patch.object(rsa, "pollard_rho", return_value=None), \
             mock.patch.object(rsa, "sympy_factor_with_timeout", return_value=None):
            self.assertIsNone(rsa.factor_weak_modulus(101, sympy_timeout=0))

    def test_pkcs1_v15_strip(self):
        block = b"\x00\x02" + b"ABCDEFGH" + b"\x00secret"
        self.assertEqual(rsa.strip_pkcs1_v15_encryption(block), b"secret")

    def test_invalid_pkcs1_not_stripped(self):
        self.assertIsNone(rsa.strip_pkcs1_v15_encryption(b"\x00\x02short\x00x"))

    def test_printable_text(self):
        self.assertEqual(rsa.printable_text(b"hello"), "hello")
        self.assertIsNone(rsa.printable_text(b"\xff\xfe"))

    def test_inspection_does_not_factor(self):
        with mock.patch.object(rsa, "factor_weak_modulus") as factor:
            rsa.inspect_values(3233, 17, 2790)
            factor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
