# Family Hub

A secure family communication platform with real-time chat, task management, notes, calendar events, and weather — built for [arivumaiyam.com](https://arivumaiyam.com).

## Features

- **Real-time Chat** — WebSocket-powered instant messaging with typing indicators
- **Task Management** — Shared todos with priorities (urgent/high/normal/low), due dates, and assignment
- **Notes** — Family-shared notes with create/edit/delete
- **Calendar Events** — Family event tracking with dates and times
- **Member Presence** — Live online/offline status for all family members
- **Weather Widget** — Current Abu Dhabi weather via Open-Meteo API
- **Secure Auth** — JWT tokens, bcrypt password hashing, rate limiting
- **Admin Controls** — Admin can manage users and moderate content
- **Password Management** — Users can change their own passwords
- **Dark Theme** — Modern dark UI with purple accent

## Tech Stack

| Layer | Tech |
|-------|------|
| Backend | Node.js + Express 5 |
| Database | SQLite (better-sqlite3, WAL mode) |
| Auth | JWT + bcrypt |
| Real-time | WebSocket (ws) |
| Security | Helmet, CORS, rate limiting, input validation |
| Frontend | Vanilla HTML/CSS/JS (no framework needed) |
| Tests | Jest + Supertest (40 tests) |

## Quick Start

```bash
# Clone
git clone https://github.com/balas072024/family-hub.git
cd family-hub

# Install
npm install

# Configure
cp .env.example .env
# Edit .env and set a strong JWT_SECRET

# Seed database with default users
npm run seed

# Start
npm start
# → http://localhost:3000
```

Default login: any username (`bala`, `wife`, `child`, `parent1`, `parent2`) with password `Family@2024`.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | No | Login, get JWT |
| GET | `/api/auth/me` | Yes | Current user |
| POST | `/api/auth/change-password` | Yes | Change password |
| GET | `/api/users` | Yes | List members |
| POST | `/api/users` | Admin | Add member |
| GET | `/api/messages?limit=50` | Yes | Chat history |
| POST | `/api/messages` | Yes | Send message |
| DELETE | `/api/messages/:id` | Owner/Admin | Delete message |
| GET | `/api/todos` | Yes | List tasks |
| POST | `/api/todos` | Yes | Create task |
| PATCH | `/api/todos/:id` | Yes | Update task |
| DELETE | `/api/todos/:id` | Owner/Admin | Delete task |
| GET | `/api/notes` | Yes | List notes |
| POST | `/api/notes` | Yes | Create note |
| PUT | `/api/notes/:id` | Owner/Admin | Update note |
| DELETE | `/api/notes/:id` | Owner/Admin | Delete note |
| GET | `/api/events` | Yes | List events |
| POST | `/api/events` | Yes | Create event |
| DELETE | `/api/events/:id` | Owner/Admin | Delete event |
| GET | `/api/health` | No | Health check |

## WebSocket

Connect to `/ws` and send:
```json
{"type": "auth", "token": "your-jwt-token"}
{"type": "chat", "content": "Hello!"}
{"type": "typing"}
```

Receive:
```json
{"type": "new_message", "message": {...}}
{"type": "typing", "userId": "...", "name": "Bala", "emoji": "👨"}
{"type": "presence", "userId": "...", "status": "online"}
```

## Testing

```bash
npm test              # Run all 40 tests
npm run test:coverage # With coverage report
```

## Docker

```bash
docker build -t family-hub .
docker run -p 3000:3000 -v family-data:/app/data family-hub
```

## Security

- Passwords hashed with bcrypt (10 rounds)
- JWT tokens with 7-day expiry
- Rate limiting: 300 req/15min (API), 20 req/15min (login)
- XSS protection via HTML escaping on frontend
- Helmet security headers
- Input validation on all endpoints
- Role-based access control (admin/member)

## License

ISC
