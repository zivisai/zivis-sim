import os
import random
import json
from faker import Faker
from uuid import uuid4
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI  # OpenAI SDK v1+

# Load environment variables (ensure OPENAI_API_KEY is set)
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Faker setup
fake = Faker()
Faker.seed(42)

# Output directory
OUTPUT_DIR = Path("generated_docs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
jsonl_path = OUTPUT_DIR / "zivis_sim.jsonl"

# Constants
ACCOUNT_TYPES = ["Checking", "Savings", "Retirement", "Investment"]
INSURANCE_TYPES = ["Life", "Auto", "Home", "Health", "Disability"]
LOAN_TYPES = ["Mortgage", "Auto Loan", "Personal Loan", "Business Loan"]

def generate_structured_data():
    return {
        "customer_id": str(uuid4()),
        "full_name": fake.name(),
        "ssn": fake.ssn(),
        "dob": fake.date_of_birth(minimum_age=21, maximum_age=75).strftime("%Y-%m-%d"),
        "address": fake.address().replace("\n", ", "),
        "email": fake.email(),
        "phone": fake.phone_number(),
        "employer": fake.company(),
        "occupation": fake.job(),
        "income": round(random.uniform(40000, 250000), 2),
        "accounts": [
            {
                "type": random.choice(ACCOUNT_TYPES),
                "number": fake.bban(),
                "balance": round(random.uniform(1000, 100000), 2)
            } for _ in range(random.randint(1, 3))
        ],
        "insurance": [
            {
                "type": random.choice(INSURANCE_TYPES),
                "policy_number": fake.bothify("??-########"),
                "coverage": round(random.uniform(50000, 1000000), 2)
            } for _ in range(random.randint(0, 2))
        ],
        "loans": [
            {
                "type": random.choice(LOAN_TYPES),
                "amount": round(random.uniform(5000, 500000), 2),
                "interest": round(random.uniform(2.5, 9.9), 2)
            } for _ in range(random.randint(0, 2))
        ],
        "credit_score": random.randint(580, 820),
        "routing_number": fake.bban()[:9],
        "iban": fake.iban(),
        "swift": fake.swift8()
    }

def create_prompt(data: dict) -> str:
    acc_str = "\n".join([f"- {a['type']}, #{a['number']}, ${a['balance']}" for a in data['accounts']])
    loan_str = "\n".join([f"- {l['type']}, ${l['amount']} at {l['interest']}%" for l in data['loans']])
    ins_str = "\n".join([f"- {i['type']} policy #{i['policy_number']}, ${i['coverage']} coverage" for i in data['insurance']])

    return f"""
You are a financial analyst at ZBank, a full-service banking and insurance company. Generate a realistic and detailed paragraph-style internal document that summarizes a client profile based on the following structured data. Use natural language, and be sure to mention all the key attributes (name, accounts, loans, insurance, etc.) in a way that reflects an internal case file.

Name: {data['full_name']}
SSN: {data['ssn']}
DOB: {data['dob']}
Address: {data['address']}
Email: {data['email']}
Phone: {data['phone']}
Employer: {data['employer']}
Occupation: {data['occupation']}
Income: ${data['income']}
Credit Score: {data['credit_score']}
Bank Routing Number: {data['routing_number']}
IBAN: {data['iban']}
SWIFT: {data['swift']}

Accounts:
{acc_str if acc_str else 'None'}

Loans:
{loan_str if loan_str else 'None'}

Insurance:
{ins_str if ins_str else 'None'}

Close the document with a sentence that confirms this file is for internal use only by ZBank.
"""

def generate_documents(n=100, max_attempts=5):
    generated = 0
    attempts = 0

    # Clear the JSONL file at start
    if jsonl_path.exists():
        jsonl_path.unlink()

    while generated < n and attempts < n * max_attempts:
        data = generate_structured_data()
        prompt = create_prompt(data)

        try:
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a financial advisor at ZBank, a full-service banking and insurance company."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7
            )

            content = response.choices[0].message.content.strip()

            # Reject if empty or too short
            if not content or len(content) < 100:
                raise ValueError("LLM returned empty or too short content.")

            # Save .txt
            file_path = OUTPUT_DIR / f"profile_{data['customer_id']}.txt"
            with open(file_path, "w") as f:
                f.write(content)

            # Save to .jsonl for Hugging Face
            with open(jsonl_path, "a") as jf:
                json.dump({"id": data["customer_id"], "content": content}, jf)
                jf.write("\n")

            print(f"✅ [{generated + 1}/{n}] Generated: {file_path}")
            generated += 1

        except Exception as e:
            print(f"❌ Attempt {attempts + 1} failed: {e}")

        attempts += 1

    if generated < n:
        print(f"⚠️ Only generated {generated} documents after {attempts} attempts.")
    else:
        print("🎉 Done generating all documents.")


if __name__ == "__main__":
    generate_documents(100)
