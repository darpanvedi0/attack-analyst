# Training settings (Unsloth Studio)

These are the settings used for the run shown in the screenshots. Run `python src/build_dataset.py` first, then upload `data/train_studio.jsonl`.

| Setting | Value |
|---|---|
| Base model | Llama-3.2-3B-Instruct |
| Method | QLoRA |
| LoRA rank / alpha | 32 / 32 |
| Epochs | 2 (348 steps) |
| Context length | 4096 |
| Learning rate | 2e-4 |
| Batch size | 2, with 4 gradient accumulation steps |
| Optimizer | AdamW 8-bit |
| LR scheduler | linear |
| Train on | Assistant completions only (the loss counts the answer, not the question) |
| Dataset | `data/train_studio.jsonl`, 1,385 chat conversations (`messages` column only) |
| Wall-clock time | about 14.5 minutes |
| Loss | 2.6077 at step 4, 0.0066 at step 348 |

See `assets/02_training_start.png`, `assets/03_training_progress.png` and `assets/04_training_completed.png` for the screens.

## Export

Export a **Q8_0 GGUF** and put it in `ollama/` as `Llama-3.2-3B-Instruct.Q8_0.gguf`, or change the `FROM` line in `ollama/Modelfile` to match your file name.

## One thing to watch: the auto-generated Modelfile

Studio's auto-generated Modelfile set `temperature 1.5`, which makes a small model ramble and invent. This repo's `ollama/Modelfile` replaces it with the Llama 3 chat template, `temperature 0.1`, `top_p 0.9` and `num_ctx 4096`. A token-count check of the Modelfile template against the training template came out equal (100 and 100), so the model sees the same prompt layout it was trained on.

## Why the data looks the way it does

`build_dataset.py` builds four kinds of conversation from the 609 training techniques only:

| Type | What it teaches |
|---|---|
| `brief` | The signature output: technique ID, tactic, platforms, summary, mitigations, detection. Questions name the ID, the name, or describe an observed behavior. |
| `fact` | Short single-fact answers: tactic, platforms, ID for a name, mitigations, parent technique. |
| `open_book` | Documents are in the prompt and the answer must come from them and cite the source file. 40% use a modified copy of the document, so the model learns to read instead of recall. |
| `abstain` | The asked-about technique or behavior is not in the documents, so the right answer is "not in the provided documents". |

The 88 techniques created after 2023-12-31 never appear. The script asserts that no held-out ID is present anywhere in the training text.
