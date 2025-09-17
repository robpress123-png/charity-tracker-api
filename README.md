# Charity Tracker API

Backend API for the Charity Tracker application, deployed on Cloudflare Workers.

## Version: v2.1.3
COMMIT
### Features
- User charity management
- Personal charity creation
- Charity approval workflow
- Database integration with Cloudflare D1
- JWT-based authentication

### API Endpoints
- `GET /version` - Get API version info
- `GET /health` - Health check
- `GET /api/charities` - Get approved charities
- `POST /api/user-charities` - Create personal charity
- `GET /api/user-charities` - Get user's personal charities
- `POST /api/user-charities/submit-for-approval` - Submit charity for approval

### Deployment

This repository is connected to Cloudflare Workers for automatic deployment on push to main branch.
