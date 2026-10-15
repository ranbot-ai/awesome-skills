---
name: 3d-web-experience
description: Use when building or debugging web 3D scenes, product configurators or portfolios with Three.js, React Three Fiber or Spline; review assets, loading, controls, fallbacks and performance. 
category: Creative & Media
source: antigravity
tags: [javascript, react, node, api, ai, agent, workflow, design, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/3d-web-experience
---


# 3D Web Experience

Expert in building 3D experiences for the web - Three.js, React Three Fiber,
Spline, WebGL, and interactive 3D scenes. Covers product configurators, 3D
portfolios, immersive websites, and bringing depth to web experiences.

**Role**: 3D Web Experience Architect

You bring the third dimension to the web. You know when 3D enhances
and when it's just showing off. You balance visual impact with
performance. You make 3D accessible to users who've never touched
a 3D app. You create moments of wonder without sacrificing usability.

### Expertise

- Three.js
- React Three Fiber
- Spline
- WebGL
- GLSL shaders
- 3D optimization
- Model preparation

## Capabilities

- Three.js implementation
- React Three Fiber
- WebGL optimization
- 3D model integration
- Spline workflows
- 3D product configurators
- Interactive 3D scenes
- 3D performance optimization

## Patterns

### 3D Stack Selection

Choosing the right 3D approach

**When to use**: When starting a 3D web project

## 3D Stack Selection

### Options Comparison
| Tool | Best For | Learning Curve | Control |
|------|----------|----------------|---------|
| Spline | Quick prototypes, designers | Low | Medium |
| React Three Fiber | React apps, complex scenes | Medium | High |
| Three.js vanilla | Max control, non-React | High | Maximum |
| Babylon.js | Games, heavy 3D | High | Maximum |

### Decision Tree
```
Need quick 3D element?
└── Yes → Spline
└── No → Continue

Using React?
└── Yes → React Three Fiber
└── No → Continue

Need max performance/control?
└── Yes → Three.js vanilla
└── No → Spline or R3F
```

### Spline (Fastest Start)
```jsx
import Spline from '@splinetool/react-spline';

export default function Scene() {
  return (
    <Spline scene="https://prod.spline.design/xxx/scene.splinecode" />
  );
}
```

### React Three Fiber
```jsx
import { Canvas } from '@react-three/fiber';
import { OrbitControls, useGLTF } from '@react-three/drei';
import { Suspense } from 'react';

function Model() {
  const { scene } = useGLTF('/model.glb');
  return <primitive object={scene} />;
}

export default function Scene() {
  return (
    <Canvas>
      <ambientLight />
      <Suspense fallback={null}>
        <Model />
      </Suspense>
      <OrbitControls enableZoom={false} />
    </Canvas>
  );
}
```

### 3D Model Pipeline

Getting models web-ready

**When to use**: When preparing 3D assets

## 3D Model Pipeline

### Format Selection
| Format | Use Case | Size |
|--------|----------|------|
| GLB/GLTF | Standard web 3D | Depends on geometry/textures/compression |
| FBX | From 3D software | Large |
| OBJ | Simple meshes | Medium |
| USDZ | Apple AR | Medium |

### Optimization Pipeline
```
1. Model in Blender/etc
2. Establish a triangle/draw-call budget on representative target devices
3. Bake textures (combine materials)
4. Export as GLB
5. Compress with gltf-transform
6. Measure transfer size, decode time, memory and frame time against the project budget
```

### GLTF Compression
```bash
# Use the reviewed version already pinned in the project lockfile.
# If absent, review and add a specific version locally before these commands.

# Compress model
./node_modules/.bin/gltf-transform optimize input.glb output.glb \
  --compress draco \
  --texture-compress webp
```

### Loading in R3F

This component needs the React/R3F/drei versions installed by the project and an
actual `/model.glb` asset. Add an application error boundary for failed asset loads.

```jsx
import { useGLTF, useProgress, Html } from '@react-three/drei';
import { Suspense } from 'react';
import { Canvas } from '@react-three/fiber';

function Model() {
  const { scene } = useGLTF('/model.glb');
  return <primitive object={scene} />;
}

function Loader() {
  const { progress } = useProgress();
  return <Html center>{progress.toFixed(0)}%</Html>;
}

export default function Scene() {
  return (
    <Canvas>
      <ambientLight />
      <Suspense fallback={<Loader />}>
        <Model />
      </Suspense>
    </Canvas>
  );
}
```

### Scroll-Driven 3D

3D that responds to scroll

**When to use**: When integrating 3D with scroll

## Scroll-Driven 3D

### R3F + Scroll Controls
```jsx
import { ScrollControls, useScroll } from '@react-three/drei';
import { Canvas, useFrame } from '@react-three/fiber';
import { useRef } from 'react';

function RotatingModel() {
  const scroll = useScroll();
  const ref = useRef();

  useFrame(() => {
    // Rotate based on scroll position
    if (ref.current) ref.current.rotation.y = scroll.offset * Math.PI * 2;
  });

  return (
    <mesh ref={ref}>
      <boxGeometry args={[1, 1, 1]} />
      <meshNormalMaterial />
    </mesh>
  );
}

export default function Scene() {
  return (
    <Canvas>
      <ScrollControls pages={3}>
        <RotatingModel />
      </ScrollControls>
    </Canvas>
  );
}
```

### GSAP + Three.js
```javascript
import gsap from 'gsap';
import ScrollTrigger from 'gsap/ScrollTrigger';

gsap.registerPlugin(ScrollTrigger);
// Integration fragm
