---
name: food-database-query
description: 本技能提供全面的营养食物数据库查询功能,支持食物营养信息查询、比较、推荐和自动营养计算。 1. 接收食物名称 2. 在数据库中搜索匹配项 3. 支持模�
category: AI & Agents
source: antigravity
tags: [python, markdown, claude, ai]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/food-database-query
---


# 食物数据库查询技能

**技能名称**: Food Database Query
**技能类型**: 数据查询与分析
**创建日期**: 2026-01-06
**版本**: v1.0

---

## 技能概述

本技能提供全面的营养食物数据库查询功能,支持食物营养信息查询、比较、推荐和自动营养计算。

**核心功能**:
- ✅ 食物营养信息查询
- ✅ 食物比较分析
- ✅ 智能食物推荐
- ✅ 自动营养计算
- ✅ 分类浏览和搜索
- ✅ 份量转换和估算

---

## 数据源

### 主数据库
- **文件**: `data/food-database.json`
- **内容**: 50种常见食物的详细营养数据
- **结构**: 每种食物包含30+营养素指标

### 分类体系
- **文件**: `data/food-categories.json`
- **分类**: 10大类,30+子类
- **支持**: 按分类浏览和筛选

---

## 功能模块

### 1. 食物查询 (Food Query)

#### 1.1 精确查询

**用途**: 根据食物名称查询营养信息

**支持输入**:
- 中文名称: "燕麦", "西兰花", "三文鱼"
- 英文名称: "Oats", "Broccoli", "Salmon"
- 别名: "燕麦片", "broccoli", "三文鱼肉"

**查询流程**:
1. 接收食物名称
2. 在数据库中搜索匹配项
3. 支持模糊匹配和别名匹配
4. 返回完整营养信息

**返回信息**:
- 基本信息 (名称、分类、标准份量)
- 宏量营养素 (卡路里、蛋白质、碳水、脂肪、纤维)
- 微量营养素 (维生素、矿物质)
- 特殊营养素 (Omega-3/6、胆碱等)
- 升糖指数数据
- 健康标签和适用人群
- 常见份量
- 营养优势说明

**示例**:
```python
# 用户输入: "燕麦"
# 返回:
{
  "name": "燕麦",
  "name_en": "Oats",
  "category": "谷物类",
  "nutrition_per_100g": {
    "calories": 389,
    "protein_g": 16.9,
    "carbs_g": 66.3,
    "fat_g": 6.9,
    "fiber_g": 10.6,
    # ... 更多营养素
  },
  "health_tags": ["高纤维", "低GI"],
  "glycemic_index": {"value": 55, "level": "低"}
}
```

#### 1.2 模糊搜索

**用途**: 根据营养特征搜索食物

**搜索条件**:
- 营养素含量: "高蛋白", "高纤维", "低GI"
- 营养素组合: "高蛋白 低卡路里", "高纤维 低GI"
- 分类筛选: "谷物类", "蔬菜", "蛋白质"
- 适用人群: "素食友好", "高血压", "糖尿病"

**搜索逻辑**:
```python
# 示例: 搜索"高蛋白 低卡路里"
def search_foods(criteria):
    results = []
    for food in database:
        protein = food.nutrition_per_100g.protein_g
        calories = food.nutrition_per_100g.calories

        # 定义阈值
        high_protein = protein >= 15  # 每100g≥15g蛋白质
        low_calorie = calories <= 150  # 每100g≤150卡

        if high_protein and low_calorie:
            results.append(food)

    return sorted(results, key=lambda x: x.protein_g, reverse=True)
```

**返回格式**:
- 按匹配度排序
- 显示关键营养素
- 标注匹配标签

#### 1.3 分类浏览

**用途**: 按食物分类浏览所有食物

**分类层级**:
```
蛋白质来源
├── 肉类
├── 禽类
├── 鱼虾贝类
├── 蛋类
├── 豆类
├── 坚果种子
└── 乳制品
```

**浏览模式**:
- 列出某分类下所有食物
- 按营养素排序
- 按GI值排序
- 按健康标签筛选

---

### 2. 食物比较 (Food Comparison)

#### 2.1 双食物比较

**功能**: 比较两种食物的营养差异

**比较维度**:
- **宏量营养素**: 卡路里、蛋白质、碳水、脂肪、纤维
- **微量营养素**: 主要维生素和矿物质
- **升糖指数**: GI值、升糖负荷
- **营养密度**: 综合评分

**计算逻辑**:
```python
def compare_foods(food1, food2):
    comparison = {}

    # 宏量营养素差异
    for nutrient in ["calories", "protein_g", "fiber_g"]:
        val1 = food1.nutrition_per_100g[nutrient]
        val2 = food2.nutrition_per_100g[nutrient]
        diff = val1 - val2
        percent = (diff / val2) * 100

        comparison[nutrient] = {
            "food1": val1,
            "food2": val2,
            "difference": diff,
            "percent_change": percent,
            "better": "food1" if diff > 0 else "food2"
        }

    return comparison
```

**输出格式**:
- 对比表格
- 差异百分比
- 优势标注
- 推荐建议

#### 2.2 多维度比较

**支持模式**:
- 全方位营养比较
- 仅比较特定营养素
- 仅比较GI值
- 仅比较特定健康标签

**示例**: `/nutrition compare 三文鱼 鸡胸肉 营养素`

---

### 3. 食物推荐 (Food Recommendation)

#### 3.1 基于营养素推荐

**推荐逻辑**:
```python
def recommend_by_nutrient(nutrient, min_value=None, max_value=None):
    recommendations = []

    for food in database:
        value = food.nutrition_per_100g[nutrient]

        # 筛选符合条件
        if min_value and value < min_value:
            continue
        if max_value and value > max_value:
            continue

        recommendations.append({
            "food": food,
            "value": value,
            "rda_percent": (value / RDA[nutrient]) * 100
        })

    # 按含量排序
    return sorted(recommendations, key=lambda x: x["value"], reverse=True)
```

**推荐类别**:
- **高蛋白**: ≥15g/100g
- **高纤维**: ≥5g/100g
- **低GI**: ≤55
- **富含维生素C**: ≥50mg/100g
- **富含Omega-3**: ≥1g/100g
- **高钙**: ≥100mg/100g
- **高铁**: ≥3mg/100g

#### 3.2 多条件推荐

**支持组合条件**:
- "高蛋白 低卡路里"
- "高纤维 低GI"
- "富含铁 素食友好"

**排序策略**:
1. 按第一优先级排序
2. 筛选符合第二条件的
3. 综合评分排序

#### 3.3 基于健康状况推荐

**高血压 (DASH饮食)**:
- 低钠食物
- 高钾食物
- 高镁、高钙食物

**糖尿病**:
- 低GI食物
- 高纤维食物
- 低碳水化合物

**高血脂**:
- 高Omega-3食物
- 低饱和脂肪
- 高纤维食物

**骨质疏松**:
- 高钙食物
- 富含维生素D
- 高镁、高锌

**贫血**:
- 富含铁
- 富含叶酸
- 富含维生素B12

---

### 4. 自动营养计算 (Auto Nutrition Calculation)

#### 4.1 食物识别

**输入解析**:
```python
def parse_food_input(text):
    # 示例: "燕麦粥 1杯 + 鸡蛋 1个 + 牛奶 250ml"

    foods = []
    portions = []

    # 识别食物名称
    for item in text.split("+"):
        food_name = extract_food_name(item)  # "燕麦粥"
        portion = extract_portion(item)      # "1杯"

        # 标准化食物名称
        standard_name = normalize_food_name(food_name)  # "燕麦"

        # 查询数据库
        food_data = query_database(standard_name)

        foods.append(food_data)
        portions.append(parse_portion(portion))

    return foods, portions
```

#### 4.2 份量转换

**常见份量**:
- "1杯": 240ml (液体) 或 重量依据食物
- "1个": 鸡蛋50g, 苹果150g
- "1片": 面包30g
- "100g": 直接使用

**份量数据库**:
```json
{
  "common_portions": [
    {
      "amount": 1,
      "unit": "个",
      "weight_g": 50,
      "description": "1个大号鸡蛋"
    },
    {
      "amount": 1,
      "unit": "杯",
      "weight_g": 240,
      "description": "1杯牛奶"
    }
  ]
}
```

#### 4.3 营养计算

**计算
