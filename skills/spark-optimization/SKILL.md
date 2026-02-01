---
name: spark-optimization
description: Optimize Apache Spark jobs with partitioning, caching, shuffle optimization, and memory tuning. Use when improving Spark performance, debugging slow jobs, or scaling data processing pipelines. 
category: AI & Agents
source: antigravity
tags: [python, ai, template, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/spark-optimization
---


# Apache Spark Optimization

Production patterns for optimizing Apache Spark jobs including partitioning strategies, memory management, shuffle optimization, and performance tuning.

## Do not use this skill when

- The task is unrelated to apache spark optimization
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Optimizing slow Spark jobs
- Tuning memory and executor configuration
- Implementing efficient partitioning strategies
- Debugging Spark performance issues
- Scaling Spark pipelines for large datasets
- Reducing shuffle and data skew

## Core Concepts

### 1. Spark Execution Model

```
Driver Program
    ↓
Job (triggered by action)
    ↓
Stages (separated by shuffles)
    ↓
Tasks (one per partition)
```

### 2. Key Performance Factors

| Factor | Impact | Solution |
|--------|--------|----------|
| **Shuffle** | Network I/O, disk I/O | Minimize wide transformations |
| **Data Skew** | Uneven task duration | Salting, broadcast joins |
| **Serialization** | CPU overhead | Use Kryo, columnar formats |
| **Memory** | GC pressure, spills | Tune executor memory |
| **Partitions** | Parallelism | Right-size partitions |

## Quick Start

```python
from pyspark.sql import SparkSession
from pyspark.sql import functions as F

# Create optimized Spark session
spark = (SparkSession.builder
    .appName("OptimizedJob")
    .config("spark.sql.adaptive.enabled", "true")
    .config("spark.sql.adaptive.coalescePartitions.enabled", "true")
    .config("spark.sql.adaptive.skewJoin.enabled", "true")
    .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
    .config("spark.sql.shuffle.partitions", "200")
    .getOrCreate())

# Read with optimized settings
df = (spark.read
    .format("parquet")
    .option("mergeSchema", "false")
    .load("s3://bucket/data/"))

# Efficient transformations
result = (df
    .filter(F.col("date") >= "2024-01-01")
    .select("id", "amount", "category")
    .groupBy("category")
    .agg(F.sum("amount").alias("total")))

result.write.mode("overwrite").parquet("s3://bucket/output/")
```

## Patterns

### Pattern 1: Optimal Partitioning

```python
# Calculate optimal partition count
def calculate_partitions(data_size_gb: float, partition_size_mb: int = 128) -> int:
    """
    Optimal partition size: 128MB - 256MB
    Too few: Under-utilization, memory pressure
    Too many: Task scheduling overhead
    """
    return max(int(data_size_gb * 1024 / partition_size_mb), 1)

# Repartition for even distribution
df_repartitioned = df.repartition(200, "partition_key")

# Coalesce to reduce partitions (no shuffle)
df_coalesced = df.coalesce(100)

# Partition pruning with predicate pushdown
df = (spark.read.parquet("s3://bucket/data/")
    .filter(F.col("date") == "2024-01-01"))  # Spark pushes this down

# Write with partitioning for future queries
(df.write
    .partitionBy("year", "month", "day")
    .mode("overwrite")
    .parquet("s3://bucket/partitioned_output/"))
```

### Pattern 2: Join Optimization

```python
from pyspark.sql import functions as F
from pyspark.sql.types import *

# 1. Broadcast Join - Small table joins
# Best when: One side < 10MB (configurable)
small_df = spark.read.parquet("s3://bucket/small_table/")  # < 10MB
large_df = spark.read.parquet("s3://bucket/large_table/")  # TBs

# Explicit broadcast hint
result = large_df.join(
    F.broadcast(small_df),
    on="key",
    how="left"
)

# 2. Sort-Merge Join - Default for large tables
# Requires shuffle, but handles any size
result = large_df1.join(large_df2, on="key", how="inner")

# 3. Bucket Join - Pre-sorted, no shuffle at join time
# Write bucketed tables
(df.write
    .bucketBy(200, "customer_id")
    .sortBy("customer_id")
    .mode("overwrite")
    .saveAsTable("bucketed_orders"))

# Join bucketed tables (no shuffle!)
orders = spark.table("bucketed_orders")
customers = spark.table("bucketed_customers")  # Same bucket count
result = orders.join(customers, on="customer_id")

# 4. Skew Join Handling
# Enable AQE skew join optimization
spark.conf.set("spark.sql.adaptive.skewJoin.enabled", "true")
spark.conf.set("spark.sql.adaptive.skewJoin.skewedPartitionFactor", "5")
spark.conf.set("spark.sql.adaptive.skewJoin.skewedPartitionThresholdInBytes", "256MB")

# Manual salting for severe skew
def salt_join(df_skewed, df_other, key_col, num_salts=10):
    """Add salt to distribute skewed keys"""
    # Add salt to skewed side
    df_salted = df_skewed.withColumn(
        "salt",
        (F.rand() * num_salts).cast("int")
    ).withColumn(
        "salted_key",
        F.concat(F.col(key_col), F.lit("_"), F.col("salt"))
    )

    # Explode other side with all salts
    df_exploded = df_other.crossJoin(
        spark.range(num_s
