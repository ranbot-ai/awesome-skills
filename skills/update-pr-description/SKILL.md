---
name: update_pr_description
description: Please check the branch "{{ BRANCH_NAME }}" and look at the diff against the main branch. This branch belongs to this PR "{{ PR_URL }}". 
category: Development & Code Tools
source: openhands
tags: [git, github, pr, agent, api]
url: https://github.com/OpenHands/OpenHands/blob/main/skills/update_pr_description.md
---


Please check the branch "{{ BRANCH_NAME }}" and look at the diff against the main branch. This branch belongs to this PR "{{ PR_URL }}".

Once you understand the purpose of the diff, please use Github API to read the existing PR description, and update it to be more reflective of the changes we've made when necessary.
