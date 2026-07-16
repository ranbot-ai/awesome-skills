---
name: diagnose-android-overheating
description: Use when diagnosing Android overheating, idle heat, thermal throttling, charging or radio heat, or abnormal battery drain with read-only ADB evidence and approval gates. 
category: Development & Code Tools
source: antigravity
tags: [claude, ai, workflow, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/diagnose-android-overheating
---


# Diagnose Android Overheating

## Overview

Find the most likely source of Android device heat by correlating thermal state, battery conditions, CPU activity, wakeups, radios, sensors, charging, and the user's timeline. Keep diagnosis read-only by default, distinguish evidence from inference, and propose only the smallest reversible intervention after the user approves it.

## When to Use This Skill

- Use when an Android phone is hot, warm while idle, thermally throttled, shutting down from heat, or draining its battery unusually fast.
- Use when heat appears during charging, weak cellular signal, 5G use, navigation, camera use, gaming, media playback, tethering, or background activity.
- Use when the user wants to identify an offending app, service, wakelock, sensor, modem condition, or charging condition through ADB.
- Use when a previous Android optimization or debloat attempt may have left settings that changed power or thermal behavior.
- Use for physical phones and tablets. For profiling the energy use of an app under development, use an app-performance skill instead.

## Safety Stop

Stop software diagnosis when the device shows battery swelling, smoke, hissing, leaking, a sharp chemical odor, repeated thermal shutdowns, or heat severe enough that it cannot be handled safely. Tell the user to disconnect power if this can be done safely, power the device off, keep it away from flammable material, and seek manufacturer or qualified repair support. Do not suggest cooling the device in a refrigerator or freezer, puncturing it, continuing to charge it, or running stress tests.

## Diagnostic Contract

Before collecting data:

1. Confirm the user owns or is authorized to inspect the device.
2. Ask what “hot” means: location on the handset, activity, charging state, network type, onset, duration, and whether the heat also occurs while idle.
3. Record the device model, Android version, recent OS/app changes, charger and cable, ambient conditions, and visible thermal warnings.
4. Explain that an attached USB cable can charge and warm the device. Use wireless ADB or short capture windows when possible, and compare with the cable disconnected.
5. Select a specific device serial when more than one ADB target is present. Never assume the first listed device is the intended phone.

## Workflow

### 1. Capture an Untouched Baseline

Do not reset Batterystats, force-stop apps, clear caches, change network modes, alter AppOps, enable battery saver, or change developer settings before preserving the initial state.

Start with read-only commands:

```bash
adb devices -l
adb -s <serial> shell getprop ro.product.manufacturer
adb -s <serial> shell getprop ro.product.model
adb -s <serial> shell getprop ro.build.version.release
adb -s <serial> shell getprop ro.build.version.sdk
adb -s <serial> shell uptime
adb -s <serial> shell dumpsys battery
adb -s <serial> shell dumpsys thermalservice
adb -s <serial> shell dumpsys cpuinfo
adb -s <serial> shell top -n 1
```

If a service or option is unavailable, record that limitation. Do not turn missing output into a healthy verdict. Android and OEM builds expose different services, fields, permissions, and `top` syntax.

### 2. Choose the Evidence Branch

Read [evidence-and-interpretation.md](references/evidence-and-interpretation.md), then collect only the branches that match the symptom:

- heat while idle: battery history, power state, alarms, jobs, sensors, location, and radios;
- heat while charging: battery/USB state and a controlled unplugged comparison;
- heat under one app: process CPU, package memory, jobs, wakelocks, network, camera, and location;
- heat in weak signal or mobile data: telephony, connectivity, signal changes, and mobile-radio activity;
- heat during camera, navigation, gaming, or playback: CPU/GPU-adjacent state, display, camera/media, sensors, location, and network activity;
- heat after a setting change: capture current values and compare them with the known previous state before proposing rollback.

Do not collect a full bugreport unless narrow evidence is insufficient. Bugreports can contain account identifiers, app activity, network details, notifications, and other sensitive data.

### 3. Reproduce with a Controlled Comparison

Define one pass/fail comparison before changing anything. Examples:

- idle with airplane mode versus idle on weak cellular signal;
- same workload on Wi-Fi versus mobile data;
- charging versus unplugged after the battery level is stable;
- suspect app active versus closed by the user;
- screen on at fixed brightness versus screen off;
- before versus after the recent OS or app update, when a real reference exists.

Keep workload, duration, brightness, case, charger, ambient conditions, and starting battery level as constant as practical. Timestamp each observation. Avoid benchmarks or synthetic load unless the user explicitly asks and the device is not already thermally stressed.

### 4. Correlate, Do Not Guess

Require at 
