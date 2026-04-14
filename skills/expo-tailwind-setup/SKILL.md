---
name: expo-tailwind-setup
description: Set up Tailwind CSS v4 in Expo with react-native-css and NativeWind v5 for universal styling 
category: AI & Agents
source: antigravity
tags: [javascript, typescript, react, api, ai, image, tailwind, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/expo-tailwind-setup
---


# Tailwind CSS Setup for Expo with react-native-css

This guide covers setting up Tailwind CSS v4 in Expo using react-native-css and NativeWind v5 for universal styling across iOS, Android, and Web.

## When to Use
- You need to set up Tailwind CSS v4 styling in an Expo app using `react-native-css` and NativeWind v5.
- The task involves configuring Metro, PostCSS, global CSS, or package versions for Expo + Tailwind.
- You want one styling setup that works across iOS, Android, and web in an Expo project.

## Overview

This setup uses:

- **Tailwind CSS v4** - Modern CSS-first configuration
- **react-native-css** - CSS runtime for React Native
- **NativeWind v5** - Metro transformer for Tailwind in React Native
- **@tailwindcss/postcss** - PostCSS plugin for Tailwind v4

## Installation

```bash
# Install dependencies
npx expo install tailwindcss@^4 nativewind@5.0.0-preview.2 react-native-css@0.0.0-nightly.5ce6396 @tailwindcss/postcss tailwind-merge clsx
```

Add resolutions for lightningcss compatibility:

```json
// package.json
{
  "resolutions": {
    "lightningcss": "1.30.1"
  }
}
```

- autoprefixer is not needed in Expo because of lightningcss
- postcss is included in expo by default

## Configuration Files

### Metro Config

Create or update `metro.config.js`:

```js
// metro.config.js
const { getDefaultConfig } = require("expo/metro-config");
const { withNativewind } = require("nativewind/metro");

/** @type {import('expo/metro-config').MetroConfig} */
const config = getDefaultConfig(__dirname);

module.exports = withNativewind(config, {
  // inline variables break PlatformColor in CSS variables
  inlineVariables: false,
  // We add className support manually
  globalClassNamePolyfill: false,
});
```

### PostCSS Config

Create `postcss.config.mjs`:

```js
// postcss.config.mjs
export default {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};
```

### Global CSS

Create `src/global.css`:

```css
@import "tailwindcss/theme.css" layer(theme);
@import "tailwindcss/preflight.css" layer(base);
@import "tailwindcss/utilities.css";

/* Platform-specific font families */
@media android {
  :root {
    --font-mono: monospace;
    --font-rounded: normal;
    --font-serif: serif;
    --font-sans: normal;
  }
}

@media ios {
  :root {
    --font-mono: ui-monospace;
    --font-serif: ui-serif;
    --font-sans: system-ui;
    --font-rounded: ui-rounded;
  }
}
```

## IMPORTANT: No Babel Config Needed

With Tailwind v4 and NativeWind v5, you do NOT need a babel.config.js for Tailwind. Remove any NativeWind babel presets if present:

```js
// DELETE babel.config.js if it only contains NativeWind config
// The following is NO LONGER needed:
// module.exports = function (api) {
//   api.cache(true);
//   return {
//     presets: [
//       ["babel-preset-expo", { jsxImportSource: "nativewind" }],
//       "nativewind/babel",
//     ],
//   };
// };
```

## CSS Component Wrappers

Since react-native-css requires explicit CSS element wrapping, create reusable components:

### Main Components (`src/tw/index.tsx`)

```tsx
import {
  useCssElement,
  useNativeVariable as useFunctionalVariable,
} from "react-native-css";

import { Link as RouterLink } from "expo-router";
import Animated from "react-native-reanimated";
import React from "react";
import {
  View as RNView,
  Text as RNText,
  Pressable as RNPressable,
  ScrollView as RNScrollView,
  TouchableHighlight as RNTouchableHighlight,
  TextInput as RNTextInput,
  StyleSheet,
} from "react-native";

// CSS-enabled Link
export const Link = (
  props: React.ComponentProps<typeof RouterLink> & { className?: string }
) => {
  return useCssElement(RouterLink, props, { className: "style" });
};

Link.Trigger = RouterLink.Trigger;
Link.Menu = RouterLink.Menu;
Link.MenuAction = RouterLink.MenuAction;
Link.Preview = RouterLink.Preview;

// CSS Variable hook
export const useCSSVariable =
  process.env.EXPO_OS !== "web"
    ? useFunctionalVariable
    : (variable: string) => `var(${variable})`;

// View
export type ViewProps = React.ComponentProps<typeof RNView> & {
  className?: string;
};

export const View = (props: ViewProps) => {
  return useCssElement(RNView, props, { className: "style" });
};
View.displayName = "CSS(View)";

// Text
export const Text = (
  props: React.ComponentProps<typeof RNText> & { className?: string }
) => {
  return useCssElement(RNText, props, { className: "style" });
};
Text.displayName = "CSS(Text)";

// ScrollView
export const ScrollView = (
  props: React.ComponentProps<typeof RNScrollView> & {
    className?: string;
    contentContainerClassName?: string;
  }
) => {
  return useCssElement(RNScrollView, props, {
    className: "style",
    contentContainerClassName: "contentContainerStyle",
  });
};
ScrollView.displayName = "CSS(ScrollView)";

// Pressable
export const Pressable = (
  props: React.ComponentProps<typeof RNPressable> & { className?: string }
) => {
  return useCssElement(RNPressable, props, { className: "style" });
};
Press
