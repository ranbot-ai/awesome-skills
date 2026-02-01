---
name: fix_test
description: Can you check out branch "{{ BRANCH_NAME }}", and run {{ TEST_COMMAND_TO_RUN }}. 
category: Development & Code Tools
source: openhands
tags: [bash, agent]
url: https://github.com/OpenHands/OpenHands/blob/main/skills/fix_test.md
---


Can you check out branch "{{ BRANCH_NAME }}", and run {{ TEST_COMMAND_TO_RUN }}.

Help me fix these tests to pass by fixing the {{ FUNCTION_TO_FIX }} function in file {{ FILE_FOR_FUNCTION }}.

PLEASE DO NOT modify the tests by yourself -- Let me know if you think some of the tests are incorrect.
