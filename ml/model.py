"""ProofPatch line-level vulnerability locator: UniXcoder encoder + per-line classifier.

Each line's tokens are mean-pooled into one vector; a small head scores every line.
A function's risk score is the maximum of its line scores.
"""
import torch
from torch import nn
from transformers import AutoModel, AutoTokenizer

BASE = 'microsoft/unixcoder-base'
MAX_TOKENS = 512


class LineLocator(nn.Module):
    def __init__(self, base=BASE):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(base)
        h = self.encoder.config.hidden_size
        self.head = nn.Sequential(nn.Dropout(0.1), nn.Linear(h, 256), nn.GELU(), nn.Linear(256, 1))

    def forward(self, input_ids, attention_mask, line_ids, n_lines):
        hidden = self.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        batch, _, dim = hidden.shape
        max_lines = int(n_lines.max().item())
        out = hidden.new_zeros(batch, max_lines, dim)
        count = hidden.new_zeros(batch, max_lines, 1)
        valid = line_ids >= 0
        idx = line_ids.clamp(min=0)
        out.scatter_add_(1, idx.unsqueeze(-1).expand(-1, -1, dim), hidden * valid.unsqueeze(-1))
        count.scatter_add_(1, idx.unsqueeze(-1), valid.unsqueeze(-1).to(hidden.dtype))
        pooled = out / count.clamp(min=1)
        return self.head(pooled).squeeze(-1)  # [batch, max_lines] logits


def encode(tokenizer, lines, max_tokens=MAX_TOKENS):
    """Tokenizes a function line by line; returns ids, per-token line index, and lines kept."""
    ids, line_ids = [tokenizer.cls_token_id], [-1]
    kept = 0
    for i, line in enumerate(lines):
        toks = tokenizer.encode(line, add_special_tokens=False)[:64] or [tokenizer.unk_token_id]
        if len(ids) + len(toks) + 1 > max_tokens:
            break
        ids += toks
        line_ids += [i] * len(toks)
        kept = i + 1
    ids.append(tokenizer.sep_token_id)
    line_ids.append(-1)
    return ids, line_ids, kept


def collate(tokenizer, batch, max_tokens=MAX_TOKENS):
    encoded = [encode(tokenizer, ex['lines'], max_tokens) for ex in batch]
    width = max(len(e[0]) for e in encoded)
    n = max(max(e[2], 1) for e in encoded)
    input_ids = torch.full((len(batch), width), tokenizer.pad_token_id)
    attention = torch.zeros((len(batch), width), dtype=torch.long)
    line_ids = torch.full((len(batch), width), -1)
    labels = torch.full((len(batch), n), -100.0)
    n_lines = torch.zeros(len(batch), dtype=torch.long)
    for b, (ids, lids, kept) in enumerate(encoded):
        input_ids[b, : len(ids)] = torch.tensor(ids)
        attention[b, : len(ids)] = 1
        line_ids[b, : len(lids)] = torch.tensor(lids)
        n_lines[b] = max(kept, 1)
        if 'labels' in batch[b]:
            labs = batch[b]['labels'][:kept]
            labels[b, : len(labs)] = torch.tensor(labs, dtype=torch.float)
    return input_ids, attention, line_ids, n_lines, labels


def load_tokenizer(path=BASE):
    return AutoTokenizer.from_pretrained(path)
