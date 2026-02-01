---
name: database-migration
description: Execute database migrations across ORMs and platforms with zero-downtime strategies, data transformation, and rollback procedures. Use when migrating databases, changing schemas, performing data trans
category: Document Processing
source: antigravity
tags: [javascript, typescript, ai, template, document, prisma, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/database-migration
---


# Database Migration

Master database schema and data migrations across ORMs (Sequelize, TypeORM, Prisma), including rollback strategies and zero-downtime deployments.

## Do not use this skill when

- The task is unrelated to database migration
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.
- If detailed examples are required, open `resources/implementation-playbook.md`.

## Use this skill when

- Migrating between different ORMs
- Performing schema transformations
- Moving data between databases
- Implementing rollback procedures
- Zero-downtime deployments
- Database version upgrades
- Data model refactoring

## ORM Migrations

### Sequelize Migrations
```javascript
// migrations/20231201-create-users.js
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('users', {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true
      },
      email: {
        type: Sequelize.STRING,
        unique: true,
        allowNull: false
      },
      createdAt: Sequelize.DATE,
      updatedAt: Sequelize.DATE
    });
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('users');
  }
};

// Run: npx sequelize-cli db:migrate
// Rollback: npx sequelize-cli db:migrate:undo
```

### TypeORM Migrations
```typescript
// migrations/1701234567-CreateUsers.ts
import { MigrationInterface, QueryRunner, Table } from 'typeorm';

export class CreateUsers1701234567 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'users',
        columns: [
          {
            name: 'id',
            type: 'int',
            isPrimary: true,
            isGenerated: true,
            generationStrategy: 'increment'
          },
          {
            name: 'email',
            type: 'varchar',
            isUnique: true
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP'
          }
        ]
      })
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('users');
  }
}

// Run: npm run typeorm migration:run
// Rollback: npm run typeorm migration:revert
```

### Prisma Migrations
```prisma
// schema.prisma
model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  createdAt DateTime @default(now())
}

// Generate migration: npx prisma migrate dev --name create_users
// Apply: npx prisma migrate deploy
```

## Schema Transformations

### Adding Columns with Defaults
```javascript
// Safe migration: add column with default
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn('users', 'status', {
      type: Sequelize.STRING,
      defaultValue: 'active',
      allowNull: false
    });
  },

  down: async (queryInterface) => {
    await queryInterface.removeColumn('users', 'status');
  }
};
```

### Renaming Columns (Zero Downtime)
```javascript
// Step 1: Add new column
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn('users', 'full_name', {
      type: Sequelize.STRING
    });

    // Copy data from old column
    await queryInterface.sequelize.query(
      'UPDATE users SET full_name = name'
    );
  },

  down: async (queryInterface) => {
    await queryInterface.removeColumn('users', 'full_name');
  }
};

// Step 2: Update application to use new column

// Step 3: Remove old column
module.exports = {
  up: async (queryInterface) => {
    await queryInterface.removeColumn('users', 'name');
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn('users', 'name', {
      type: Sequelize.STRING
    });
  }
};
```

### Changing Column Types
```javascript
module.exports = {
  up: async (queryInterface, Sequelize) => {
    // For large tables, use multi-step approach

    // 1. Add new column
    await queryInterface.addColumn('users', 'age_new', {
      type: Sequelize.INTEGER
    });

    // 2. Copy and transform data
    await queryInterface.sequelize.query(`
      UPDATE users
      SET age_new = CAST(age AS INTEGER)
      WHERE age IS NOT NULL
    `);

    // 3. Drop old column
    await queryInterface.removeColumn('users', 'age');

    // 4. Rename new column
    await queryInterface.renameColumn('users', 'age_new', 'age');
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.changeColumn('users', 'age', {
      type: Sequelize.STRING
    });
  }
};
```

## Data Transformations

### Complex Data Migration
```javascript
module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Get all records
    const [users] 
