---
name: moodle-external-api-development
description: Create custom external web service APIs for Moodle LMS. Use when implementing web services for course management, user tracking, quiz operations, or custom plugin functionality. Covers parameter valid
category: Document Processing
source: antigravity
tags: [javascript, api, ai, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/moodle-external-api-development
---


# Moodle External API Development

This skill guides you through creating custom external web service APIs for Moodle LMS, following Moodle's external API framework and coding standards.

## When to Use This Skill

- Creating custom web services for Moodle plugins
- Implementing REST/AJAX endpoints for course management
- Building APIs for quiz operations, user tracking, or reporting
- Exposing Moodle functionality to external applications
- Developing mobile app backends using Moodle

## Core Architecture Pattern

Moodle external APIs follow a strict three-method pattern:

1. **`execute_parameters()`** - Defines input parameter structure
2. **`execute()`** - Contains business logic
3. **`execute_returns()`** - Defines return structure

## Step-by-Step Implementation

### Step 1: Create the External API Class File

**Location**: `/local/yourplugin/classes/external/your_api_name.php`

```php
<?php
namespace local_yourplugin\external;

defined('MOODLE_INTERNAL') || die();
require_once("$CFG->libdir/externallib.php");

use external_api;
use external_function_parameters;
use external_single_structure;
use external_value;

class your_api_name extends external_api {
    
    // Three required methods will go here
    
}
```

**Key Points**:
- Class must extend `external_api`
- Namespace follows: `local_pluginname\external` or `mod_modname\external`
- Include the security check: `defined('MOODLE_INTERNAL') || die();`
- Require externallib.php for base classes

### Step 2: Define Input Parameters

```php
public static function execute_parameters() {
    return new external_function_parameters([
        'userid' => new external_value(PARAM_INT, 'User ID', VALUE_REQUIRED),
        'courseid' => new external_value(PARAM_INT, 'Course ID', VALUE_REQUIRED),
        'options' => new external_single_structure([
            'includedetails' => new external_value(PARAM_BOOL, 'Include details', VALUE_DEFAULT, false),
            'limit' => new external_value(PARAM_INT, 'Result limit', VALUE_DEFAULT, 10)
        ], 'Options', VALUE_OPTIONAL)
    ]);
}
```

**Common Parameter Types**:
- `PARAM_INT` - Integers
- `PARAM_TEXT` - Plain text (HTML stripped)
- `PARAM_RAW` - Raw text (no cleaning)
- `PARAM_BOOL` - Boolean values
- `PARAM_FLOAT` - Floating point numbers
- `PARAM_ALPHANUMEXT` - Alphanumeric with extended chars

**Structures**:
- `external_value` - Single value
- `external_single_structure` - Object with named fields
- `external_multiple_structure` - Array of items

**Value Flags**:
- `VALUE_REQUIRED` - Parameter must be provided
- `VALUE_OPTIONAL` - Parameter is optional
- `VALUE_DEFAULT, defaultvalue` - Optional with default

### Step 3: Implement Business Logic

```php
public static function execute($userid, $courseid, $options = []) {
    global $DB, $USER;

    // 1. Validate parameters
    $params = self::validate_parameters(self::execute_parameters(), [
        'userid' => $userid,
        'courseid' => $courseid,
        'options' => $options
    ]);

    // 2. Check permissions/capabilities
    $context = \context_course::instance($params['courseid']);
    self::validate_context($context);
    require_capability('moodle/course:view', $context);

    // 3. Verify user access
    if ($params['userid'] != $USER->id) {
        require_capability('moodle/course:viewhiddenactivities', $context);
    }

    // 4. Database operations
    $sql = "SELECT id, name, timecreated
            FROM {your_table}
            WHERE userid = :userid
              AND courseid = :courseid
            LIMIT :limit";
    
    $records = $DB->get_records_sql($sql, [
        'userid' => $params['userid'],
        'courseid' => $params['courseid'],
        'limit' => $params['options']['limit']
    ]);

    // 5. Process and return data
    $results = [];
    foreach ($records as $record) {
        $results[] = [
            'id' => $record->id,
            'name' => $record->name,
            'timestamp' => $record->timecreated
        ];
    }

    return [
        'items' => $results,
        'count' => count($results)
    ];
}
```

**Critical Steps**:
1. **Always validate parameters** using `validate_parameters()`
2. **Check context** using `validate_context()`
3. **Verify capabilities** using `require_capability()`
4. **Use parameterized queries** to prevent SQL injection
5. **Return structured data** matching return definition

### Step 4: Define Return Structure

```php
public static function execute_returns() {
    return new external_single_structure([
        'items' => new external_multiple_structure(
            new external_single_structure([
                'id' => new external_value(PARAM_INT, 'Item ID'),
                'name' => new external_value(PARAM_TEXT, 'Item name'),
                'timestamp' => new external_value(PARAM_INT, 'Creation time')
            ])
        ),
        'count' => new external_value(PARAM_INT, 'Total items')
    ]);
}
```

**Return Structure Rules**:
- Must match exactly what `execute()` re
