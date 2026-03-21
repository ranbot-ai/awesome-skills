---
name: react-flow-architect
description: Build production-ready ReactFlow applications with hierarchical navigation, performance optimization, and advanced state management. 
category: AI & Agents
source: antigravity
tags: [javascript, typescript, react, node, api, ai, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/react-flow-architect
---


# ReactFlow Architect

Build production-ready ReactFlow applications with hierarchical navigation, performance optimization, and advanced state management.

## Quick Start

Create basic interactive graph:

```tsx
import ReactFlow, { Node, Edge } from "reactflow";

const nodes: Node[] = [
  { id: "1", position: { x: 0, y: 0 }, data: { label: "Node 1" } },
  { id: "2", position: { x: 100, y: 100 }, data: { label: "Node 2" } },
];

const edges: Edge[] = [{ id: "e1-2", source: "1", target: "2" }];

export default function Graph() {
  return <ReactFlow nodes={nodes} edges={edges} />;
}
```

## Core Patterns

### Hierarchical Tree Navigation

Build expandable/collapsible tree structures with parent-child relationships.

#### Node Schema

```typescript
interface TreeNode extends Node {
  data: {
    label: string;
    level: number;
    hasChildren: boolean;
    isExpanded: boolean;
    childCount: number;
    category: "root" | "category" | "process" | "detail";
  };
}
```

#### Incremental Node Building

```typescript
const buildVisibleNodes = useCallback(
  (allNodes: TreeNode[], expandedIds: Set<string>, otherDeps: any[]) => {
    const visibleNodes = new Map<string, TreeNode>();
    const visibleEdges = new Map<string, TreeEdge>();

    // Start with root nodes
    const rootNodes = allNodes.filter((n) => n.data.level === 0);

    // Recursively add visible nodes
    const addVisibleChildren = (node: TreeNode) => {
      visibleNodes.set(node.id, node);

      if (expandedIds.has(node.id)) {
        const children = allNodes.filter((n) => n.parentNode === node.id);
        children.forEach((child) => addVisibleChildren(child));
      }
    };

    rootNodes.forEach((root) => addVisibleChildren(root));

    return {
      nodes: Array.from(visibleNodes.values()),
      edges: Array.from(visibleEdges.values()),
    };
  },
  [],
);
```

### Performance Optimization

Handle large datasets with incremental rendering and memoization.

#### Incremental Rendering

```typescript
const useIncrementalGraph = (
  allNodes: Node[],
  allEdges: Edge[],
  expandedList: string[],
) => {
  const prevExpandedListRef = useRef<Set<string>>(new Set());
  const prevOtherDepsRef = useRef<any[]>([]);

  const { visibleNodes, visibleEdges } = useMemo(() => {
    const currentExpandedSet = new Set(expandedList);
    const prevExpandedSet = prevExpandedListRef.current;

    // Check if expanded list changed
    const expandedChanged = !areSetsEqual(currentExpandedSet, prevExpandedSet);

    // Check if other dependencies changed
    const otherDepsChanged = !arraysEqual(otherDeps, prevOtherDepsRef.current);

    if (expandedChanged && !otherDepsChanged) {
      // Only expanded list changed - incremental update
      return buildIncrementalUpdate(
        cachedVisibleNodesRef.current,
        cachedVisibleEdgesRef.current,
        allNodes,
        allEdges,
        currentExpandedSet,
        prevExpandedSet,
      );
    } else {
      // Full rebuild needed
      return buildFullGraph(allNodes, allEdges, currentExpandedSet);
    }
  }, [allNodes, allEdges, expandedList, ...otherDeps]);

  return { visibleNodes, visibleEdges };
};
```

#### Memoization Patterns

```typescript
// Memoize node components to prevent unnecessary re-renders
const ProcessNode = memo(({ data, selected }: NodeProps) => {
  return (
    <div className={`process-node ${selected ? 'selected' : ''}`}>
      {data.label}
    </div>
  );
}, (prevProps, nextProps) => {
  // Custom comparison function
  return (
    prevProps.data.label === nextProps.data.label &&
    prevProps.selected === nextProps.selected &&
    prevProps.data.isExpanded === nextProps.data.isExpanded
  );
});

// Memoize edge calculations
const styledEdges = useMemo(() => {
  return edges.map(edge => ({
    ...edge,
    style: {
      ...edge.style,
      strokeWidth: selectedEdgeId === edge.id ? 3 : 2,
      stroke: selectedEdgeId === edge.id ? '#3b82f6' : '#94a3b8',
    },
    animated: selectedEdgeId === edge.id,
  }));
}, [edges, selectedEdgeId]);
```

### State Management

Complex node/edge state patterns with undo/redo and persistence.

#### Reducer Pattern

```typescript
type GraphAction =
  | { type: "SELECT_NODE"; payload: string }
  | { type: "SELECT_EDGE"; payload: string }
  | { type: "TOGGLE_EXPAND"; payload: string }
  | { type: "UPDATE_NODES"; payload: Node[] }
  | { type: "UPDATE_EDGES"; payload: Edge[] }
  | { type: "UNDO" }
  | { type: "REDO" };

const graphReducer = (state: GraphState, action: GraphAction): GraphState => {
  switch (action.type) {
    case "SELECT_NODE":
      return {
        ...state,
        selectedNodeId: action.payload,
        selectedEdgeId: null,
      };

    case "TOGGLE_EXPAND":
      const newExpanded = new Set(state.expandedNodeIds);
      if (newExpanded.has(action.payload)) {
        newExpanded.delete(action.payload);
      } else {
        newExpanded.add(action.payload);
      }
      return {
        ...state,
        expandedNodeIds: ne
