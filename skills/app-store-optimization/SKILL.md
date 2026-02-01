---
name: app-store-optimization
description: Complete App Store Optimization (ASO) toolkit for researching, optimizing, and tracking mobile app performance on Apple App Store and Google Play Store 
category: Creative & Media
source: antigravity
tags: [claude, ai, template, design, firebase, rag, seo, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/app-store-optimization
---


# App Store Optimization (ASO) Skill

This comprehensive skill provides complete ASO capabilities for successfully launching and optimizing mobile applications on the Apple App Store and Google Play Store.

## Capabilities

### Research & Analysis
- **Keyword Research**: Analyze keyword volume, competition, and relevance for app discovery
- **Competitor Analysis**: Deep-dive into top-performing apps in your category
- **Market Trend Analysis**: Identify emerging trends and opportunities in your app category
- **Review Sentiment Analysis**: Extract insights from user reviews to identify strengths and issues
- **Category Analysis**: Evaluate optimal category and subcategory placement strategies

### Metadata Optimization
- **Title Optimization**: Create compelling titles with optimal keyword placement (platform-specific character limits)
- **Description Optimization**: Craft both short and full descriptions that convert and rank
- **Subtitle/Promotional Text**: Optimize Apple-specific subtitle (30 chars) and promotional text (170 chars)
- **Keyword Field**: Maximize Apple's 100-character keyword field with strategic selection
- **Category Selection**: Data-driven recommendations for primary and secondary categories
- **Icon Best Practices**: Guidelines for designing high-converting app icons
- **Screenshot Optimization**: Strategies for creating screenshots that drive installs
- **Preview Video**: Best practices for app preview videos
- **Localization**: Multi-language optimization strategies for global reach

### Conversion Optimization
- **A/B Testing Framework**: Plan and track metadata experiments for continuous improvement
- **Visual Asset Testing**: Test icons, screenshots, and videos for maximum conversion
- **Store Listing Optimization**: Comprehensive page optimization for impression-to-install conversion
- **Call-to-Action**: Optimize CTAs in descriptions and promotional materials

### Rating & Review Management
- **Review Monitoring**: Track and analyze user reviews for actionable insights
- **Response Strategies**: Templates and best practices for responding to reviews
- **Rating Improvement**: Tactical approaches to improve app ratings organically
- **Issue Identification**: Surface common problems and feature requests from reviews

### Launch & Update Strategies
- **Pre-Launch Checklist**: Complete validation before submitting to stores
- **Launch Timing**: Optimize release timing for maximum visibility and downloads
- **Update Cadence**: Plan optimal update frequency and feature rollouts
- **Feature Announcements**: Craft "What's New" sections that re-engage users
- **Seasonal Optimization**: Leverage seasonal trends and events

### Analytics & Tracking
- **ASO Score**: Calculate overall ASO health score across multiple factors
- **Keyword Rankings**: Track keyword position changes over time
- **Conversion Metrics**: Monitor impression-to-install conversion rates
- **Download Velocity**: Track download trends and momentum
- **Performance Benchmarking**: Compare against category averages and competitors

### Platform-Specific Requirements
- **Apple App Store**:
  - Title: 30 characters
  - Subtitle: 30 characters
  - Promotional Text: 170 characters (editable without app update)
  - Description: 4,000 characters
  - Keywords: 100 characters (comma-separated, no spaces)
  - What's New: 4,000 characters
- **Google Play Store**:
  - Title: 50 characters (formerly 30, increased in 2021)
  - Short Description: 80 characters
  - Full Description: 4,000 characters
  - No separate keyword field (keywords extracted from title and description)

## Input Requirements

### Keyword Research
```json
{
  "app_name": "MyApp",
  "category": "Productivity",
  "target_keywords": ["task manager", "productivity", "todo list"],
  "competitors": ["Todoist", "Any.do", "Microsoft To Do"],
  "language": "en-US"
}
```

### Metadata Optimization
```json
{
  "platform": "apple" | "google",
  "app_info": {
    "name": "MyApp",
    "category": "Productivity",
    "target_audience": "Professionals aged 25-45",
    "key_features": ["Task management", "Team collaboration", "AI assistance"],
    "unique_value": "AI-powered task prioritization"
  },
  "current_metadata": {
    "title": "Current Title",
    "subtitle": "Current Subtitle",
    "description": "Current description..."
  },
  "target_keywords": ["productivity", "task manager", "todo"]
}
```

### Review Analysis
```json
{
  "app_id": "com.myapp.app",
  "platform": "apple" | "google",
  "date_range": "last_30_days" | "last_90_days" | "all_time",
  "rating_filter": [1, 2, 3, 4, 5],
  "language": "en"
}
```

### ASO Score Calculation
```json
{
  "metadata": {
    "title_quality": 0.8,
    "description_quality": 0.7,
    "keyword_density": 0.6
  },
  "ratings": {
    "average_rating": 4.5,
    "total_ratings": 15000
  },
  "conversion": {
    "impression_to_install": 0.05
  },
  "keyword_rankings": {
    "top_10": 5,
    "top_50": 12,
    "top_100": 18
  }
}
```

## Output
