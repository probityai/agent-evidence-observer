---
base_model: HuggingFaceTB/SmolLM2-360M-Instruct
language:
- en
library_name: transformers
license: apache-2.0
tags:
- llama
- unsloth
- transformers
---

# Finetune SmolLM2, Llama 3.2, Gemma 2, Mistral 2-5x faster with 70% less memory via Unsloth!

We have a free Google Colab Tesla T4 notebook for Llama 3.2 (3B) here: https://colab.research.google.com/drive/1Ys44kVvmeZtnICzWz0xgpRnrIOjZAuxp?usp=sharing

[<img src="https://raw.githubusercontent.com/unslothai/unsloth/main/images/Discord%20button.png" width="200"/>](https://discord.gg/unsloth)
[<img src="https://raw.githubusercontent.com/unslothai/unsloth/main/images/unsloth%20made%20with%20love.png" width="200"/>](https://github.com/unslothai/unsloth)

# unsloth/SmolLM2-360M-Instruct-GGUF
For more details on the model, please go to Hugging Face's original [model card](https://huggingface.co/HuggingFaceTB/SmolLM2-360M-Instruct)

## ✨ Finetune for Free

All notebooks are **beginner friendly**! Add your dataset, click "Run All", and you'll get a 2x faster finetuned model which can be exported to GGUF, vLLM or uploaded to Hugging Face.

| Unsloth supports          |    Free Notebooks                                                                                           | Performance | Memory use |
|-----------------|--------------------------------------------------------------------------------------------------------------------------|-------------|----------|
| **Llama-3.2 (3B)**      | [▶️ Start on Colab](https://colab.research.google.com/drive/1Ys44kVvmeZtnICzWz0xgpRnrIOjZAuxp?usp=sharing)               | 2.4x faster | 58% less |
| **Llama-3.2 (11B vision)**      | [▶️ Start on Colab](https://colab.research.google.com/drive/1Ys44kVvmeZtnICzWz0xgpRnrIOjZAuxp?usp=sharing)               | 2.4x faster | 58% less |
| **Llama-3.1 (8B)**      | [▶️ Start on Colab](https://colab.research.google.com/drive/1Ys44kVvmeZtnICzWz0xgpRnrIOjZAuxp?usp=sharing)               | 2.4x faster | 58% less |
| **Phi-3.5 (mini)** | [▶️ Start on Colab](https://colab.research.google.com/drive/1lN6hPQveB_mHSnTOYifygFcrO8C1bxq4?usp=sharing)               | 2x faster | 50% less |
| **Gemma 2 (9B)**      | [▶️ Start on Colab](https://colab.research.google.com/drive/1vIrqH5uYDQwsJ4-OO3DErvuv4pBgVwk4?usp=sharing)               | 2.4x faster | 58% less |
| **Mistral (7B)**    | [▶️ Start on Colab](https://colab.research.google.com/drive/1Dyauq4kTZoLewQ1cApceUQVNcnnNTzg_?usp=sharing)               | 2.2x faster | 62% less |
| **DPO - Zephyr**     | [▶️ Start on Colab](https://colab.research.google.com/drive/15vttTpzzVXv_tJwEk-hIcQ0S9FcEWvwP?usp=sharing)               | 1.9x faster | 19% less |

- This [conversational notebook](https://colab.research.google.com/drive/1Aau3lgPzeZKQ-98h69CCu1UJcvIBLmy2?usp=sharing) is useful for ShareGPT ChatML / Vicuna templates.
- This [text completion notebook](https://colab.research.google.com/drive/1ef-tab5bhkvWmBOObepl1WgJvfvSzn5Q?usp=sharing) is for raw text. This [DPO notebook](https://colab.research.google.com/drive/15vttTpzzVXv_tJwEk-hIcQ0S9FcEWvwP?usp=sharing) replicates Zephyr.
- \* Kaggle has 2x T4s, but we use 1. Due to overhead, 1x T4 is 5x faster.

## Special Thanks
A huge thank you to the Hugging Face team for creating and releasing these models.

## Model Summary

SmolLM2 is a family of compact language models available in three size: 135M, 360M, and 1.7B parameters. They are capable of solving a wide range of tasks while being lightweight enough to run on-device.

The 1.7B variant demonstrates significant advances over its predecessor SmolLM1-1.7B, particularly in instruction following, knowledge, reasoning, and mathematics. It was trained on 11 trillion tokens using a diverse dataset combination: FineWeb-Edu, DCLM, The Stack, along with new mathematics and coding datasets that we curated and will release soon. We developed the instruct version through supervised fine-tuning (SFT) using a combination of public datasets and our own curated datasets. We then applied Direct Preference Optimization (DPO) using [UltraFeedback](https://huggingface.co/datasets/HuggingFaceH4/ultrafeedback_binarized).

The instruct model additionally supports tasks such as text rewriting, summarization and function calling thanks to datasets developed by [Argilla](https://huggingface.co/argilla) such as [Synth-APIGen-v0.1](https://huggingface.co/datasets/argilla/Synth-APIGen-v0.1).

# SmolLM2

![image/png](https://cdn-uploads.huggingface.co/production/uploads/61c141342aac764ce1654e43/y45hIMNREW7w_XpHYB_0q.png)