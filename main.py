import openai
import json
import os
from dotenv import load_dotenv

openai.api_key = "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"

def generate_response(prompt):
    response = openai.Completion.create(
        engine="text-davinci-002",  # Replace with the GPT-4 model name when available
        prompt=prompt,
        max_tokens=100,
        n=1,
        stop=None,
        temperature=0.7,
    )

    return response.choices[0].text.strip()
    return result

if __name__ == "__main__":
    prompt = "What is the best cell phone plan for a customer who needs unlimited data and international calling?"
    response = generate_response(prompt)
    print(response)
