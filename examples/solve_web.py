"""
Example: Solving a Web CTF Challenge

This example demonstrates how to use the CTF Agent to solve
a typical web security challenge.
"""

from agent import CTFAgent


def solve_web_challenge():
    """Solve a web SQL injection challenge."""
    agent = CTFAgent(
        model="gpt-4o",
        max_iterations=15,
        timeout=300,
    )

    result = agent.solve(
        challenge_url="http://challenge.ctf.com/login",
        challenge_text="""
        Challenge: Login as admin
        Hint: The login form is vulnerable to SQL injection.
        Find the admin password and get the flag.
        """,
        category="web",
    )

    print(f"Result: {result}")
    if result.success:
        print(f"🎉 Flag: {result.flag}")
        print(f"📊 Steps taken: {result.iterations}")
        print(f"⏱️ Time: {result.elapsed_time:.1f}s")

        print("\n📝 Solving steps:")
        for i, step in enumerate(result.steps, 1):
            print(f"  {i}. {step}")
    else:
        print(f"❌ Failed: {result.error}")


if __name__ == "__main__":
    solve_web_challenge()
