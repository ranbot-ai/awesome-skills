---
name: hugging-face-papers
description: Read and analyze Hugging Face paper pages or arXiv papers with markdown and papers API metadata. 
category: AI & Agents
source: antigravity
tags: [pdf, markdown, api, ai]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/hugging-face-papers
---


# Hugging Face Paper Pages

Hugging Face Paper pages (hf.co/papers) is a platform built on top of arXiv (arxiv.org), specifically for research papers in the field of artificial intelligence (AI) and computer science. Hugging Face users can submit their paper at hf.co/papers/submit, which features it on the Daily Papers feed (hf.co/papers). Each day, users can upvote papers and comment on papers. Each paper page allows authors to:
- claim their paper (by clicking their name on the `authors` field). This makes the paper page appear on their Hugging Face profile.
- link the associated model checkpoints, datasets and Spaces by including the HF paper or arXiv URL in the model card, dataset card or README of the Space
- link the Github repository and/or project page URLs
- link the HF organization. This also makes the paper page appear on the Hugging Face organization page.

Whenever someone mentions a HF paper or arXiv abstract/PDF URL in a model card, dataset card or README of a Space repository, the paper will be automatically indexed. Note that not all papers indexed on Hugging Face are also submitted to daily papers. The latter is more a manner of promoting a research paper. Papers can only be submitted to daily papers up until 14 days after their publication date on arXiv.

The Hugging Face team has built an easy-to-use API to interact with paper pages. Content of the papers can be fetched as markdown, or structured metadata can be returned such as author names, linked models/datasets/spaces, linked Github repo and project page.

## When to Use
- User shares a Hugging Face paper page URL (e.g. `https://huggingface.co/papers/2602.08025`)
- User shares a Hugging Face markdown paper page URL (e.g. `https://huggingface.co/papers/2602.08025.md`)
- User shares an arXiv URL (e.g. `https://arxiv.org/abs/2602.08025` or  `https://arxiv.org/pdf/2602.08025`)
- User mentions a arXiv ID (e.g. `2602.08025`)
- User asks you to summarize, explain, or analyze an AI research paper

## Parsing the paper ID

It's recommended to parse the paper ID (arXiv ID) from whatever the user provides:

| Input | Paper ID |
| --- | --- |
| `https://huggingface.co/papers/2602.08025` | `2602.08025` |
| `https://huggingface.co/papers/2602.08025.md` | `2602.08025` |
| `https://arxiv.org/abs/2602.08025` | `2602.08025` |
| `https://arxiv.org/pdf/2602.08025` | `2602.08025` |
| `2602.08025v1` | `2602.08025v1` |
| `2602.08025` | `2602.08025` |

This allows you to provide the paper ID into any of the hub API endpoints mentioned below.

### Fetch the paper page as markdown

The content of a paper can be fetched as markdown like so:

```bash
curl -s "https://huggingface.co/papers/{PAPER_ID}.md"
```

This should return the Hugging Face paper page as markdown. This relies on the HTML version of the paper at https://arxiv.org/html/{PAPER_ID}.

There are 2 exceptions:
- Not all arXiv papers have an HTML version. If the HTML version of the paper does not exist, then the content falls back to the HTML of the Hugging Face paper page.
- If it results in a 404, it means the paper is not yet indexed on hf.co/papers. See [Error handling](#error-handling) for info.

Alternatively, you can request markdown from the normal paper page URL, like so:

```bash
curl -s -H "Accept: text/markdown" "https://huggingface.co/papers/{PAPER_ID}"
```

### Paper Pages API Endpoints

All endpoints use the base URL `https://huggingface.co`.

#### Get structured metadata

Fetch the paper metadata as JSON using the Hugging Face REST API:

```bash
curl -s "https://huggingface.co/api/papers/{PAPER_ID}"
```

This returns structured metadata that can include:

- authors (names and Hugging Face usernames, in case they have claimed the paper)
- media URLs (uploaded when submitting the paper to Daily Papers)
- summary (abstract) and AI-generated summary
- project page and GitHub repository
- organization and engagement metadata (number of upvotes)

To find models linked to the paper, use:

```bash
curl https://huggingface.co/api/models?filter=arxiv:{PAPER_ID}
```

To find datasets linked to the paper, use:

```bash
curl https://huggingface.co/api/datasets?filter=arxiv:{PAPER_ID}
```

To find spaces linked to the paper, use:

```bash
curl https://huggingface.co/api/spaces?filter=arxiv:{PAPER_ID}
```

#### Claim paper authorship

Claim authorship of a paper for a Hugging Face user:

```bash
curl "https://huggingface.co/api/settings/papers/claim" \
  --request POST \
  --header "Content-Type: application/json" \
  --header "Authorization: Bearer $HF_TOKEN" \
  --data '{
    "paperId": "{PAPER_ID}",
    "claimAuthorId": "{AUTHOR_ENTRY_ID}",
    "targetUserId": "{USER_ID}"
  }'
```

- Endpoint: `POST /api/settings/papers/claim`
- Body:
  - `paperId` (string, required): arXiv paper identifier being claimed
  - `claimAuthorId` (string): author entry on the paper being claimed, 24-char hex ID
  - `targetUserId` (string): HF user who should receive the claim, 24-char hex ID
- Response: paper authors
