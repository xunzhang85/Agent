"""
Example: Solving a Crypto CTF Challenge

Demonstrates using the agent for cryptographic challenges.
"""

from agent import CTFAgent


def solve_crypto_challenge():
    """Solve an RSA challenge with weak primes."""
    agent = CTFAgent(model="gpt-4o")

    result = agent.solve(
        challenge_text="""
        Challenge: RSA Decryption
        n = 0xb0bee1e19563af3e076898dc8b2c43d8c6cc0523e276529c49c7a1895574e9b1
        e = 0x10001
        c = 0x6a2c32c49c32a17c8d36c3f2c4e032a583a6c1b2d7f0e8c9a1b2c3d4e5f6
        Hint: The prime factors of n are very close together.
        """,
        category="crypto",
    )

    print(f"Result: {result}")
    if result.success:
        print(f"🎉 Flag: {result.flag}")


if __name__ == "__main__":
    solve_crypto_challenge()
