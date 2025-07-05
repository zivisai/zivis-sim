# 🧪 Zivis Sim – AI Security Simulation Environment

**Zivis Sim** is a modular simulation environment for testing, demonstrating, and analyzing AI-specific security vulnerabilities — including RAG pipelines, embedding attacks, SSE hijacking, and more.

Built to support red teaming and adversarial testing scenarios, `zivis-sim` helps security engineers, researchers, and AI teams explore the real-world risks of integrating LLMs and vector search into products.

## 🔍 Features

- Simulates OWASP Top 10 LLM vulnerabilities
- Interactive RAG pipeline for realistic testing
- Embedding vector manipulation and inversion scenarios
- SSE stream hijack & replay simulation
- Dockerized environment with Redis, Postgres (pgvector), and Python/.NET APIs
- Designed for agent-driven automated red teaming

## 🚀 Use Cases

- ✅ AI security assessments
- ✅ Red team simulations
- ✅ Safe testing of real-world AI threat vectors
- ✅ Educational demos and security research

## 📦 Stack

- Python (FastAPI)
- Redis, PostgreSQL + pgvector
- SSE streaming architecture (coming soon)
- Docker + `docker-compose`

## Set Up

### Local Environment Setup

This project is built to run smoothly in a local environment using Docker. Below are the steps to get everything up and running:

#### Requirements
- **Python** (version X.X.X or above)  
  Ensure that you have Python installed in your environment if you're not using Docker.

#### Docker Setup (Recommended)

Using Docker is the easiest way to test the project, as it automatically sets up all necessary components.

1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/yourusername/yourrepo.git
   cd yourrepo


#### Generate Docs
It is highly recommend to use the zivis-sim dataset hosted on hugging face.
https://huggingface.co/datasets/zivis/zivis-sim

However, the script generate-docs.py may be used to generate documents to be used in testing. 

GitHub is senstive about storing PII/PHI and so hugging face is. amore apporaite store for this data


## OWASP LLM Top 10 (2024)

These are the top security risks identified by OWASP for large language model (LLM) applications:

1. **LLM01: Prompt Injection**  
   Attackers manipulate prompts to alter model behavior or bypass intended functionality.

2. **LLM02: Insecure Output Handling**  
   Unsafe handling of model outputs that can lead to command execution, data leakage, or XSS.

3. **LLM03: Training Data Poisoning**  
   Malicious data introduced during training to influence model responses.

4. **LLM04: Model Denial of Service (DoS)**  
   Overloading the model with expensive or recursive inputs to degrade service.

5. **LLM05: Supply Chain Vulnerabilities**  
   Risks introduced via dependencies, model weights, plugins, or libraries.

6. **LLM06: Sensitive Information Disclosure**  
   Unintended leakage of confidential data memorized during training or exposed via prompt context.

7. **LLM07: Insecure Plugin Design**  
   Plugins or tools that interact with the LLM without proper authentication or access control.

8. **LLM08: Excessive Agency**  
   Over-delegation of decision-making or actions to the LLM without guardrails.

9. **LLM09: Overreliance**  
   Blind trust in model outputs without validation, leading to poor or dangerous outcomes.

10. **LLM10: Model Theft**  
   Unauthorized extraction or replication of proprietary model weights or functionality.

> Source: [OWASP LLM Top 10 (2024)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)


## 📄 License

This project is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

We chose Apache 2.0 because it’s a permissive open source license that:
- ✅ Allows commercial and non-commercial use
- ✅ Supports modification and redistribution
- ✅ Provides an explicit **patent grant**, offering extra legal protection for users and contributors

This makes it a good fit for both individual developers and companies.






## About Zivis

Zivis is a company dedicated to enhancing AI security, focusing on building innovative tools and solutions for adversarial testing, vulnerability simulation, and security assessments. Our mission is to help businesses, especially in the AI space, secure their systems against the rapidly evolving landscape of AI-specific vulnerabilities.

At Zivis, we specialize in the following areas:
- **AI Security Testing:** Using red teaming and penetration testing techniques to identify weaknesses in AI systems.
- **Vulnerability Simulations:** Simulating real-world attacks to demonstrate potential security risks and enhance defensive measures.
- **AI-Specific Threats:** Exploring and addressing vulnerabilities unique to AI models, including RAG pipelines, embedding systems, and large language models (LLMs).

By sharing our open-source projects, we aim to foster collaboration and contribute to the broader AI security community. We believe in the power of open-source collaboration to drive innovation and improve the security posture of AI technologies.

For more information, visit our website: [Zivis.ai](https://zivis.ai)



## Classes of Vulnerabilties

| **Category**                             | **Subsurface**                                                                 | **Example Vulnerabilities / Attacks**                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| **RAG (Retrieval-Augmented Generation)** | - Vector Store Injection<br>- Index Poisoning<br>- Embedding Reversal          | - Overlapping embedding manipulation<br>- Unauthorized PII leakage<br>- Prompt injection via retrieved docs |
| **Agents**                               | - Tool Misuse<br>- Role Drift<br>- Delegation Loops                            | - Agent tool spoofing<br>- Multi-hop goal hijack<br>- Instruction-following cascade                         |
| **Streaming (SSE)**                      | - SSE Hijack<br>- Replay Attacks<br>- Data Race                                | - SSE stream sniffing<br>- Stream injection or tampering<br>- Race condition between user & AI agent        |
| **MCP (Model Context Protocol)**         | - Unsafe Chain-of-Thought<br>- Context Overflow<br>- Response Filtering Bypass | - Prompt-leak via thought-chaining<br>- Contextual poisoning<br>- Filter evasion via linguistic tricks      |
| **Embedding Systems**                    | - Inversion<br>- Leakage<br>- Misalignment                                     | - Embedding vector inversion<br>- Label leakage via similar vectors<br>- False semantic positives           |
| **LLM APIs / Frontends**                 | - Rate Exploitation<br>- Input Tunneling<br>- Output Tuning                    | - Bulk scraping of completions<br>- Encoding bypasses<br>- CORS misconfig exploitation                      |
| **Privacy / PII**                        | - Memory Leakage<br>- Extraction via Repetition                                | - Memorized data retrieval<br>- Temperature-based enumeration attacks                                       |
| **LangChain / Framework-specific**       | - Chain Misconfig<br>- Tool Exposure                                           | - Tool visibility beyond intended chain<br>- Reused memory across chains                                    |

