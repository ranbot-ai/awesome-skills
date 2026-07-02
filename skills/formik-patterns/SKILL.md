---
name: formik-patterns
description: Formik form handling with validation patterns. Use when building forms, implementing validation, or handling form submission. 
category: AI & Agents
source: antigravity
tags: [typescript, react, api, claude, ai, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/formik-patterns
---


# Formik Patterns
## When to Use

Use this skill when you need formik form handling with validation patterns. Use when building forms, implementing validation, or handling form submission.


## Basic Form Setup

```tsx
import { useFormik } from 'formik';
import * as yup from 'yup';

const validationSchema = yup.object({
  email: yup.string().email('Invalid email').required('Email is required'),
  password: yup.string().min(8, 'Min 8 characters').required('Password is required'),
});

const LoginForm = () => {
  const formik = useFormik({
    initialValues: {
      email: '',
      password: '',
    },
    validationSchema,
    onSubmit: async (values) => {
      await loginMutation({ variables: { input: values } });
    },
  });

  return (
    <VStack gap="$4">
      <Input
        label="Email"
        value={formik.values.email}
        onChangeText={formik.handleChange('email')}
        onBlur={formik.handleBlur('email')}
        error={formik.touched.email ? formik.errors.email : undefined}
        keyboardType="email-address"
        autoCapitalize="none"
      />

      <Input
        label="Password"
        value={formik.values.password}
        onChangeText={formik.handleChange('password')}
        onBlur={formik.handleBlur('password')}
        error={formik.touched.password ? formik.errors.password : undefined}
        secureTextEntry
      />

      <Button
        onPress={formik.handleSubmit}
        isDisabled={!formik.isValid || formik.isSubmitting}
        isLoading={formik.isSubmitting}
      >
        Login
      </Button>
    </VStack>
  );
};
```

## Validation Schemas

### Common Patterns

```typescript
import * as yup from 'yup';

// Email
email: yup.string()
  .email('Invalid email address')
  .required('Email is required')

// Password with requirements
password: yup.string()
  .min(8, 'Must be at least 8 characters')
  .matches(/[a-z]/, 'Must contain lowercase letter')
  .matches(/[A-Z]/, 'Must contain uppercase letter')
  .matches(/[0-9]/, 'Must contain number')
  .required('Password is required')

// Confirm password
confirmPassword: yup.string()
  .oneOf([yup.ref('password')], 'Passwords must match')
  .required('Please confirm password')

// Phone number
phone: yup.string()
  .matches(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number')
  .required('Phone is required')

// Optional field with validation when present
website: yup.string()
  .url('Must be a valid URL')
  .nullable()

// Number with range
quantity: yup.number()
  .min(1, 'Minimum 1')
  .max(100, 'Maximum 100')
  .required('Quantity required')

// Array with minimum items
tags: yup.array()
  .of(yup.string())
  .min(1, 'Select at least one tag')
```

### Conditional Validation

```typescript
const schema = yup.object({
  hasCompany: yup.boolean(),
  companyName: yup.string().when('hasCompany', {
    is: true,
    then: (schema) => schema.required('Company name required'),
    otherwise: (schema) => schema.nullable(),
  }),
});
```

## Form Field Helpers

### Input Helper

```tsx
const getFieldProps = (name: keyof typeof formik.values) => ({
  value: formik.values[name],
  onChangeText: formik.handleChange(name),
  onBlur: formik.handleBlur(name),
  error: formik.touched[name] ? formik.errors[name] : undefined,
});

// Usage
<Input label="Email" {...getFieldProps('email')} />
```

### Select/Picker Helper

```tsx
<Select
  label="Country"
  value={formik.values.country}
  onValueChange={(value) => formik.setFieldValue('country', value)}
  error={formik.touched.country ? formik.errors.country : undefined}
  options={countryOptions}
/>
```

## Form Submission with GraphQL

```tsx
const CreateItemForm = () => {
  const [createItem] = useCreateItemMutation({
    onCompleted: () => {
      toast.success({ title: 'Item created' });
      navigation.goBack();
    },
    onError: (error) => {
      console.error('createItem failed:', error);
      toast.error({ title: 'Failed to create item' });
    },
  });

  const formik = useFormik({
    initialValues: { name: '', description: '' },
    validationSchema,
    onSubmit: async (values, { setSubmitting }) => {
      try {
        await createItem({ variables: { input: values } });
      } finally {
        setSubmitting(false);
      }
    },
  });

  return (
    <VStack gap="$4">
      {/* Form fields */}
      <Button
        onPress={formik.handleSubmit}
        isDisabled={!formik.isValid || formik.isSubmitting}
        isLoading={formik.isSubmitting}
      >
        Create
      </Button>
    </VStack>
  );
};
```

## Edit Form with Initial Values

```tsx
const EditItemForm = ({ item }: { item: Item }) => {
  const [updateItem] = useUpdateItemMutation({
    onCompleted: () => toast.success({ title: 'Saved' }),
    onError: (error) => {
      console.error('updateItem failed:', error);
      toast.error({ title: 'Save failed' });
    },
  });

  const formik = useFormik({
    initialValues: {
      name: item.name,
      description: item.description ?? '',
    },
    enable
