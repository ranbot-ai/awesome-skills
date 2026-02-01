---
name: invoice-organizer
description: Automatically organizes invoices and receipts for tax preparation by reading messy files, extracting key information, renaming them consistently, and sorting them into logical folders. Turns hours of 
category: Productivity & Organization
source: awesome-llm
tags: [pdf, markdown, api, claude, ai, automation, image, invoice, organizer]
url: https://github.com/Prat011/awesome-llm-skills/tree/master/invoice-organizer
---


# Invoice Organizer

This skill transforms chaotic folders of invoices, receipts, and financial documents into a clean, tax-ready filing system without manual effort.

## When to Use This Skill

- Preparing for tax season and need organized records
- Managing business expenses across multiple vendors
- Organizing receipts from a messy folder or email downloads
- Setting up automated invoice filing for ongoing bookkeeping
- Archiving financial records by year or category
- Reconciling expenses for reimbursement
- Preparing documentation for accountants

## What This Skill Does

1. **Reads Invoice Content**: Extracts information from PDFs, images, and documents:
   - Vendor/company name
   - Invoice number
   - Date
   - Amount
   - Product or service description
   - Payment method

2. **Renames Files Consistently**: Creates standardized filenames:
   - Format: `YYYY-MM-DD Vendor - Invoice - ProductOrService.pdf`
   - Examples: `2024-03-15 Adobe - Invoice - Creative Cloud.pdf`

3. **Organizes by Category**: Sorts into logical folders:
   - By vendor
   - By expense category (software, office, travel, etc.)
   - By time period (year, quarter, month)
   - By tax category (deductible, personal, etc.)

4. **Handles Multiple Formats**: Works with:
   - PDF invoices
   - Scanned receipts (JPG, PNG)
   - Email attachments
   - Screenshots
   - Bank statements

5. **Maintains Originals**: Preserves original files while organizing copies

## How to Use

### Basic Usage

Navigate to your messy invoice folder:
```
cd ~/Desktop/receipts-to-sort
```

Then ask Claude Code:
```
Organize these invoices for taxes
```

Or more specifically:
```
Read all invoices in this folder, rename them to 
"YYYY-MM-DD Vendor - Invoice - Product.pdf" format, 
and organize them by vendor
```

### Advanced Organization

```
Organize these invoices:
1. Extract date, vendor, and description from each file
2. Rename to standard format
3. Sort into folders by expense category (Software, Office, Travel, etc.)
4. Create a CSV spreadsheet with all invoice details for my accountant
```

## Instructions

When a user requests invoice organization:

1. **Scan the Folder**
   
   Identify all invoice files:
   ```bash
   # Find all invoice-related files
   find . -type f \( -name "*.pdf" -o -name "*.jpg" -o -name "*.png" \) -print
   ```
   
   Report findings:
   - Total number of files
   - File types
   - Date range (if discernible from names)
   - Current organization (or lack thereof)

2. **Extract Information from Each File**
   
   For each invoice, extract:
   
   **From PDF invoices**:
   - Use text extraction to read invoice content
   - Look for common patterns:
     - "Invoice Date:", "Date:", "Issued:"
     - "Invoice #:", "Invoice Number:"
     - Company name (usually at top)
     - "Amount Due:", "Total:", "Amount:"
     - "Description:", "Service:", "Product:"
   
   **From image receipts**:
   - Read visible text from images
   - Identify vendor name (often at top)
   - Look for date (common formats)
   - Find total amount
   
   **Fallback for unclear files**:
   - Use filename clues
   - Check file creation/modification date
   - Flag for manual review if critical info missing

3. **Determine Organization Strategy**
   
   Ask user preference if not specified:
   
   ```markdown
   I found [X] invoices from [date range].
   
   How would you like them organized?
   
   1. **By Vendor** (Adobe/, Amazon/, Stripe/, etc.)
   2. **By Category** (Software/, Office Supplies/, Travel/, etc.)
   3. **By Date** (2024/Q1/, 2024/Q2/, etc.)
   4. **By Tax Category** (Deductible/, Personal/, etc.)
   5. **Custom** (describe your structure)
   
   Or I can use a default structure: Year/Category/Vendor
   ```

4. **Create Standardized Filename**
   
   For each invoice, create a filename following this pattern:
   
   ```
   YYYY-MM-DD Vendor - Invoice - Description.ext
   ```
   
   Examples:
   - `2024-03-15 Adobe - Invoice - Creative Cloud.pdf`
   - `2024-01-10 Amazon - Receipt - Office Supplies.pdf`
   - `2023-12-01 Stripe - Invoice - Monthly Payment Processing.pdf`
   
   **Filename Best Practices**:
   - Remove special characters except hyphens
   - Capitalize vendor names properly
   - Keep descriptions concise but meaningful
   - Use consistent date format (YYYY-MM-DD) for sorting
   - Preserve original file extension

5. **Execute Organization**
   
   Before moving files, show the plan:
   
   ```markdown
   # Organization Plan
   
   ## Proposed Structure
   ```
   Invoices/
   ├── 2023/
   │   ├── Software/
   │   │   ├── Adobe/
   │   │   └── Microsoft/
   │   ├── Services/
   │   └── Office/
   └── 2024/
       ├── Software/
       ├── Services/
       └── Office/
   ```
   
   ## Sample Changes
   
   Before: `invoice_adobe_march.pdf`
   After: `2024-03-15 Adobe - Invoice - Creative Cloud.pdf`
   Location: `Invoices/2024/Software/Adobe/`
   
   Before: `IMG_2847.jpg`
   After: `2024-02-10 Staples - Receipt - Office Supplies.jpg`
   Lo
