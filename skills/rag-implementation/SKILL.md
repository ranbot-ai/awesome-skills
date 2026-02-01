---
name: rag-implementation
description: Build Retrieval-Augmented Generation (RAG) systems for LLM applications with vector databases and semantic search. Use when implementing knowledge-grounded AI, building document Q&A systems, or integr
category: Document Processing
source: antigravity
tags: [python, markdown, api, ai, llm, template, document, gcp, langchain, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/rag-implementation
---


# RAG Implementation

Master Retrieval-Augmented Generation (RAG) to build LLM applications that provide accurate, grounded responses using external knowledge sources.

## Use this skill when

- Building Q&A systems over proprietary documents
- Creating chatbots with current, factual information
- Implementing semantic search with natural language queries
- Reducing hallucinations with grounded responses
- Enabling LLMs to access domain-specific knowledge
- Building documentation assistants
- Creating research tools with source citation

## Do not use this skill when

- You only need purely generative writing without retrieval
- The dataset is too small to justify embeddings
- You cannot store or process the source data safely

## Instructions

1. Define the corpus, update cadence, and evaluation targets.
2. Choose embedding models and vector store based on scale.
3. Build ingestion, chunking, and retrieval with reranking.
4. Evaluate with grounded QA metrics and monitor drift.

## Safety

- Redact sensitive data and enforce access controls.
- Avoid exposing source documents in responses when restricted.

## Core Components

### 1. Vector Databases
**Purpose**: Store and retrieve document embeddings efficiently

**Options:**
- **Pinecone**: Managed, scalable, fast queries
- **Weaviate**: Open-source, hybrid search
- **Milvus**: High performance, on-premise
- **Chroma**: Lightweight, easy to use
- **Qdrant**: Fast, filtered search
- **FAISS**: Meta's library, local deployment

### 2. Embeddings
**Purpose**: Convert text to numerical vectors for similarity search

**Models:**
- **text-embedding-ada-002** (OpenAI): General purpose, 1536 dims
- **all-MiniLM-L6-v2** (Sentence Transformers): Fast, lightweight
- **e5-large-v2**: High quality, multilingual
- **Instructor**: Task-specific instructions
- **bge-large-en-v1.5**: SOTA performance

### 3. Retrieval Strategies
**Approaches:**
- **Dense Retrieval**: Semantic similarity via embeddings
- **Sparse Retrieval**: Keyword matching (BM25, TF-IDF)
- **Hybrid Search**: Combine dense + sparse
- **Multi-Query**: Generate multiple query variations
- **HyDE**: Generate hypothetical documents

### 4. Reranking
**Purpose**: Improve retrieval quality by reordering results

**Methods:**
- **Cross-Encoders**: BERT-based reranking
- **Cohere Rerank**: API-based reranking
- **Maximal Marginal Relevance (MMR)**: Diversity + relevance
- **LLM-based**: Use LLM to score relevance

## Quick Start

```python
from langchain.document_loaders import DirectoryLoader
from langchain.text_splitters import RecursiveCharacterTextSplitter
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import Chroma
from langchain.chains import RetrievalQA
from langchain.llms import OpenAI

# 1. Load documents
loader = DirectoryLoader('./docs', glob="**/*.txt")
documents = loader.load()

# 2. Split into chunks
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=200,
    length_function=len
)
chunks = text_splitter.split_documents(documents)

# 3. Create embeddings and vector store
embeddings = OpenAIEmbeddings()
vectorstore = Chroma.from_documents(chunks, embeddings)

# 4. Create retrieval chain
qa_chain = RetrievalQA.from_chain_type(
    llm=OpenAI(),
    chain_type="stuff",
    retriever=vectorstore.as_retriever(search_kwargs={"k": 4}),
    return_source_documents=True
)

# 5. Query
result = qa_chain({"query": "What are the main features?"})
print(result['result'])
print(result['source_documents'])
```

## Advanced RAG Patterns

### Pattern 1: Hybrid Search
```python
from langchain.retrievers import BM25Retriever, EnsembleRetriever

# Sparse retriever (BM25)
bm25_retriever = BM25Retriever.from_documents(chunks)
bm25_retriever.k = 5

# Dense retriever (embeddings)
embedding_retriever = vectorstore.as_retriever(search_kwargs={"k": 5})

# Combine with weights
ensemble_retriever = EnsembleRetriever(
    retrievers=[bm25_retriever, embedding_retriever],
    weights=[0.3, 0.7]
)
```

### Pattern 2: Multi-Query Retrieval
```python
from langchain.retrievers.multi_query import MultiQueryRetriever

# Generate multiple query perspectives
retriever = MultiQueryRetriever.from_llm(
    retriever=vectorstore.as_retriever(),
    llm=OpenAI()
)

# Single query → multiple variations → combined results
results = retriever.get_relevant_documents("What is the main topic?")
```

### Pattern 3: Contextual Compression
```python
from langchain.retrievers import ContextualCompressionRetriever
from langchain.retrievers.document_compressors import LLMChainExtractor

compressor = LLMChainExtractor.from_llm(llm)

compression_retriever = ContextualCompressionRetriever(
    base_compressor=compressor,
    base_retriever=vectorstore.as_retriever()
)

# Returns only relevant parts of documents
compressed_docs = compression_retriever.get_relevant_documents("query")
```

### Pattern 4: Parent Document Retriever
```python
from langchain.retrievers import ParentDocumentRetriever
