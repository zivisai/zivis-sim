import os
import random
import json
from uuid import uuid4
from pathlib import Path
from dotenv import load_dotenv
from faker import Faker
import openai

# Load environment variables (ensure OPENAI_API_KEY is set)
load_dotenv()
# Note: With openai>=1.0.0, the API key is typically handled by the client,
# which automatically reads the OPENAI_API_KEY environment variable.
# Setting openai.api_key is now legacy.

# Faker setup
fake = Faker()
Faker.seed(42)

# Output directory
OUTPUT_DIR = Path("generated_docs")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
jsonl_path = OUTPUT_DIR / "maul.jsonl"

# Constants
ACCOUNT_TYPES = ["Checking", "Savings", "Retirement", "Investment"]
INSURANCE_TYPES = ["Life", "Auto", "Home", "Health", "Disability"]
LOAN_TYPES = ["Mortgage", "Auto Loan", "Personal Loan", "Business Loan"]

def generate_structured_data():
    """
    Generate structured data for a fake customer profile.
    """
    customer_id = str(uuid4())
    full_name = fake.name()
    ssn = fake.ssn()
    dob = fake.date_of_birth(minimum_age=21, maximum_age=75).strftime("%Y-%m-%d")
    address = fake.address().replace("\n", ", ")
    email = fake.email()
    phone = fake.phone_number()
    employer = fake.company()
    occupation = fake.job()
    income = round(random.uniform(40000, 250000), 2)
    role = random.choice(["admin", "manager", "analyst", "customer_service", "executive", "advisor", "intern"])

    data = {
        "customer_id": customer_id,
        "full_name": full_name,
        "ssn": ssn,
        "dob": dob,
        "address": address,
        "email": email,
        "phone": phone,
        "employer": employer,
        "occupation": occupation,
        "income": income,
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

    metadata = {
        "id": customer_id,  # Unique identifier for the document
        "role": role,  # Set to role for RBAC, can be dynamically changed at runtime
        "customer_id": customer_id,
        "full_name": full_name,
        "ssn": ssn,
        "dob": dob,
        "income": income,
        "credit_score": data["credit_score"],
        "account_types": [a["type"] for a in data["accounts"]],
        "insurance_types": [i["type"] for i in data["insurance"]],
        "loan_types": [l["type"] for l in data["loans"]],
        "address": address
    }

    return data, metadata

def create_prompt(data: dict) -> str:
    """
    Create a prompt for generating a client profile based on structured data.
    """
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
    """
    Generate a specified number of documents and save them in .jsonl formats.
    """
    # 1. Initialize the OpenAI Client
    # The client automatically finds the OPENAI_API_KEY environment variable.
    try:
        client = openai.OpenAI()
    except openai.OpenAIError as e:
        print(f"Error initializing OpenAI client: {e}")
        print("Please ensure your OPENAI_API_KEY environment variable is set correctly.")
        return

    generated = 0
    attempts = 0

    if jsonl_path.exists():
        jsonl_path.unlink()

    while generated < n and attempts < n * max_attempts:
        data, metadata = generate_structured_data()
        prompt = create_prompt(data)

        try:
            # 2. Call the new chat completions endpoint with the correct parameters
            response = client.chat.completions.create(
                model="gpt-4",  # Or "gpt-3.5-turbo"
                messages=[
                    {"role": "user", "content": prompt} # 3. Structure the input as a messages list
                ],
                temperature=0.7,
                max_tokens=250 # Increased max_tokens as 150 can be a bit short for the detailed output
            )

            # 4. Access the response content from the new object structure
            content = response.choices[0].message.content.strip()

            if not content or len(content) < 100:
                # This is a good check to keep
                raise ValueError("LLM returned empty or too short content.")

            with open(jsonl_path, "a", encoding='utf-8') as jf: # Added encoding for safety
                json.dump({"id": data["customer_id"], "content": content, "metadata": metadata}, jf)
                jf.write("\n")

            print(f"✅ [{generated + 1}/{n}] Generated successfully.")
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