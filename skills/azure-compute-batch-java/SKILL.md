---
name: azure-compute-batch-java
description: Azure Batch SDK for Java. Run large-scale parallel and HPC batch jobs with pools, jobs, tasks, and compute nodes. Triggers: "BatchClient java", "azure batch java", "batch pool java", "batch job java",
category: Document Processing
source: antigravity
tags: [node, api, ai, document, image, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-compute-batch-java
---


# Azure Batch SDK for Java

Client library for running large-scale parallel and high-performance computing (HPC) batch jobs in Azure.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-compute-batch</artifactId>
    <version>1.0.0-beta.5</version>
</dependency>
```

## Prerequisites

- Azure Batch account
- Pool configured with compute nodes
- Azure subscription

## Environment Variables

```bash
AZURE_BATCH_ENDPOINT=https://<account>.<region>.batch.azure.com
AZURE_BATCH_ACCOUNT=<account-name>
AZURE_BATCH_ACCESS_KEY=<account-key>
```

## Client Creation

### With Microsoft Entra ID (Recommended)

```java
import com.azure.compute.batch.BatchClient;
import com.azure.compute.batch.BatchClientBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;

BatchClient batchClient = new BatchClientBuilder()
    .credential(new DefaultAzureCredentialBuilder().build())
    .endpoint(System.getenv("AZURE_BATCH_ENDPOINT"))
    .buildClient();
```

### Async Client

```java
import com.azure.compute.batch.BatchAsyncClient;

BatchAsyncClient batchAsyncClient = new BatchClientBuilder()
    .credential(new DefaultAzureCredentialBuilder().build())
    .endpoint(System.getenv("AZURE_BATCH_ENDPOINT"))
    .buildAsyncClient();
```

### With Shared Key Credentials

```java
import com.azure.core.credential.AzureNamedKeyCredential;

String accountName = System.getenv("AZURE_BATCH_ACCOUNT");
String accountKey = System.getenv("AZURE_BATCH_ACCESS_KEY");
AzureNamedKeyCredential sharedKeyCreds = new AzureNamedKeyCredential(accountName, accountKey);

BatchClient batchClient = new BatchClientBuilder()
    .credential(sharedKeyCreds)
    .endpoint(System.getenv("AZURE_BATCH_ENDPOINT"))
    .buildClient();
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Pool | Collection of compute nodes that run tasks |
| Job | Logical grouping of tasks |
| Task | Unit of computation (command/script) |
| Node | VM that executes tasks |
| Job Schedule | Recurring job creation |

## Pool Operations

### Create Pool

```java
import com.azure.compute.batch.models.*;

batchClient.createPool(new BatchPoolCreateParameters("myPoolId", "STANDARD_DC2s_V2")
    .setVirtualMachineConfiguration(
        new VirtualMachineConfiguration(
            new BatchVmImageReference()
                .setPublisher("Canonical")
                .setOffer("UbuntuServer")
                .setSku("22_04-lts")
                .setVersion("latest"),
            "batch.node.ubuntu 22.04"))
    .setTargetDedicatedNodes(2)
    .setTargetLowPriorityNodes(0), null);
```

### Get Pool

```java
BatchPool pool = batchClient.getPool("myPoolId");
System.out.println("Pool state: " + pool.getState());
System.out.println("Current dedicated nodes: " + pool.getCurrentDedicatedNodes());
```

### List Pools

```java
import com.azure.core.http.rest.PagedIterable;

PagedIterable<BatchPool> pools = batchClient.listPools();
for (BatchPool pool : pools) {
    System.out.println("Pool: " + pool.getId() + ", State: " + pool.getState());
}
```

### Resize Pool

```java
import com.azure.core.util.polling.SyncPoller;

BatchPoolResizeParameters resizeParams = new BatchPoolResizeParameters()
    .setTargetDedicatedNodes(4)
    .setTargetLowPriorityNodes(2);

SyncPoller<BatchPool, BatchPool> poller = batchClient.beginResizePool("myPoolId", resizeParams);
poller.waitForCompletion();
BatchPool resizedPool = poller.getFinalResult();
```

### Enable AutoScale

```java
BatchPoolEnableAutoScaleParameters autoScaleParams = new BatchPoolEnableAutoScaleParameters()
    .setAutoScaleEvaluationInterval(Duration.ofMinutes(5))
    .setAutoScaleFormula("$TargetDedicatedNodes = min(10, $PendingTasks.GetSample(TimeInterval_Minute * 5));");

batchClient.enablePoolAutoScale("myPoolId", autoScaleParams);
```

### Delete Pool

```java
SyncPoller<BatchPool, Void> deletePoller = batchClient.beginDeletePool("myPoolId");
deletePoller.waitForCompletion();
```

## Job Operations

### Create Job

```java
batchClient.createJob(
    new BatchJobCreateParameters("myJobId", new BatchPoolInfo().setPoolId("myPoolId"))
        .setPriority(100)
        .setConstraints(new BatchJobConstraints()
            .setMaxWallClockTime(Duration.ofHours(24))
            .setMaxTaskRetryCount(3)),
    null);
```

### Get Job

```java
BatchJob job = batchClient.getJob("myJobId", null, null);
System.out.println("Job state: " + job.getState());
```

### List Jobs

```java
PagedIterable<BatchJob> jobs = batchClient.listJobs(new BatchJobsListOptions());
for (BatchJob job : jobs) {
    System.out.println("Job: " + job.getId() + ", State: " + job.getState());
}
```

### Get Task Counts

```java
BatchTaskCountsResult counts = batchClient.getJobTaskCounts("myJobId");
System.out.println("Active: " + counts.getTaskCounts().getActive());
System.out.println("Running: " + counts.getTaskCounts().getRunning());
System.out.println("Completed: " + counts.getTaskCounts().getCompleted());
```

### Termin
