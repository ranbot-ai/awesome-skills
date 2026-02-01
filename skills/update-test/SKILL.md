---
name: update_test
description: Can you check out branch "{{ BRANCH_NAME }}", and run {{ TEST_COMMAND_TO_RUN }}. 
category: Development & Code Tools
source: openhands
tags: [bash, agent]
url: https://github.com/OpenHands/OpenHands/blob/main/skills/update_test.md
---


Can you check out branch "{{ BRANCH_NAME }}", and run {{ TEST_COMMAND_TO_RUN }}.

The current implementation of the code is correct BUT the test functions {{ FUNCTION_TO_FIX }} in file {{ FILE_FOR_FUNCTION }} are failing.

Please update the test file so that they pass with the current version of the implementation.
