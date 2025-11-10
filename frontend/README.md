# MySSO Frontend

Next.js frontend for the MySSO authentication system.

## Features

- User registration with validation
- User login
- Protected dashboard
- Token refresh mechanism
- Secure logout
- Form validation (email, password strength)

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env.local
   ```
   
   Update `.env.local` with your backend API URL (default: `http://localhost:3000`)

3. **Run development server:**
   ```bash
   npm run dev
   ```
   
   The app will be available at `http://localhost:3001`

## Build

```bash
npm run build
npm start
```

## Environment Variables

- `NEXT_PUBLIC_API_URL` - Backend API URL (required)

## Pages

- `/` - Landing page
- `/login` - Login page
- `/register` - Registration page
- `/dashboard` - Protected user dashboard

## Tech Stack

- Next.js 16 (App Router)
- TypeScript
- TailwindCSS
- React Context for state management

## Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
