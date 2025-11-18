# StorX Developer Console - Frontend

Vue.js frontend application for the StorX Developer Console.

## Project Structure

This project follows the same structure as the StorX Admin Web application:

```
satellite/developer/ui/
├── build/                    # Production build output (generated)
├── node_modules/             # NPM dependencies (generated)
├── public/                   # Static public assets
├── src/                      # Source code directory
│   ├── api/                  # API client and services
│   ├── assets/               # Static assets (processed by Vite)
│   ├── components/           # Reusable Vue components
│   ├── layouts/              # Layout components
│   ├── plugins/              # Vue plugins setup
│   ├── router/               # Vue Router configuration
│   ├── store/                # Pinia state management
│   ├── styles/               # Global styles
│   ├── types/                # TypeScript type definitions
│   ├── utils/                # Utility functions
│   ├── views/                # Page components (routes)
│   ├── App.vue               # Root Vue component
│   └── main.ts               # Application entry point
├── .eslintrc.js             # ESLint configuration
├── .gitignore               # Git ignore rules
├── index.html               # HTML entry point
├── package.json             # NPM dependencies and scripts
├── tsconfig.json            # TypeScript configuration
└── vite.config.js           # Vite build configuration
```

## Setup

### Install Dependencies

```bash
cd satellite/developer/ui
npm install
```

### Development

```bash
npm run dev
```

Starts the development server on port 3001 (configured in `vite.config.js`).

### Build

```bash
npm run build
```

Builds the application for production. Output goes to `build/` directory.

### Preview

```bash
npm run preview
```

Preview the production build locally.

## Features

### Authentication Flow

1. **Email Link with Token**: Developer receives email with JWT token link
2. **Token Verification**: Link opens login page, token is verified
3. **First Login**: Developer uses temporary credentials from email
4. **Password Reset**: After first login, automatically redirected to reset password
5. **Second Login**: Developer logs in with new password
6. **Dashboard Access**: Full access to developer console

### Pages

- **Login** (`/login`): Login page with token verification support
- **Reset Password** (`/reset-password`): Password reset page (token-based or post-login)
- **Dashboard** (`/dashboard`): Main dashboard with overview cards
- **OAuth Clients** (`/dashboard/oauth-clients`): Manage OAuth2 clients
- **Settings** (`/dashboard/settings`): Account settings and password change

### API Integration

All API calls are handled through `src/api/developerApi.ts` which communicates with:
- `/api/v0/developer/auth/*` endpoints

### State Management

Uses Pinia for state management:
- `auth` store: Authentication state, account info, login/logout actions

## Configuration

### API Proxy

The development server proxies `/api` requests to `http://localhost:8080` (configured in `vite.config.js`).

### Build Output

Production builds output to `build/` directory, which can be served by the backend server.

## Integration with Backend

The frontend is designed to be:
1. **Development**: Served by Vite dev server (port 3001) with API proxy
2. **Production**: Built and served as static files by the backend server

The backend server (`satellite/developer/server.go`) serves static files from the `build/` directory.

