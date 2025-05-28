# NestJS Authentication System - API Design & Flow

## Required NPM Libraries

```bash
npm install @nestjs/jwt @nestjs/passport @nestjs/config
npm install passport passport-local passport-jwt passport-google-oauth20 passport-github2
npm install bcrypt nodemailer
npm install class-validator class-transformer
npm install @types/passport-local @types/passport-jwt @types/bcrypt @types/nodemailer --save-dev
```

---

## 1. Login API

### Controller Function Arguments
- `email`: string (required)
- `password`: string (required)

### Step-by-Step Logic Flow
I. **Input Validation**
   - Validate email format using class-validator
   - Check if email and password are provided
   - Return BadRequestException if validation fails

II. **User Existence Check**
   - Query database to find user by email
   - If user doesn't exist, return UnauthorizedException with generic message

III. **Account Status Verification**
   - Check if user account is active/verified
   - If account is deactivated or unverified, return appropriate exception

IV. **Password Verification**
   - Use bcrypt.compare() to verify password against stored hash
   - If password is invalid, return UnauthorizedException

V. **JWT Token Generation**
   - Create JWT payload with user ID, email, and roles
   - Generate access token with short expiration (15-30 minutes)
   - Generate refresh token with longer expiration (7-30 days)

VI. **Update User Session**
   - Store refresh token in database (optional)
   - Update last login timestamp
   - Log successful login attempt

VII. **Response Formation**
   - Return access token, refresh token, user info (excluding password)
   - Include token expiration times

### Libraries Used
- `bcrypt` for password comparison
- `@nestjs/jwt` for token generation
- `class-validator` for input validation

---

## 2. Signup API

### Controller Function Arguments
- `email`: string (required)
- `password`: string (required)
- `firstName`: string (required)
- `lastName`: string (required)
- `confirmPassword`: string (required)

### Step-by-Step Logic Flow
I. **Input Validation**
   - Validate email format and uniqueness
   - Check password strength (minimum 8 chars, special chars, etc.)
   - Verify password and confirmPassword match
   - Validate required fields are present

II. **User Existence Check**
   - Query database to check if email already exists
   - If user exists, return ConflictException

III. **Password Hashing**
   - Use bcrypt.hash() with salt rounds (10-12) to hash password
   - Store hashed password, never plain text

IV. **User Creation**
   - Create new user record in database
   - Set initial status (active/pending verification)
   - Generate unique user ID

V. **Email Verification Setup** (Optional)
   - Generate email verification token
   - Store token with expiration time
   - Send verification email using nodemailer

VI. **JWT Token Generation**
   - Create JWT payload with user info
   - Generate access and refresh tokens
   - Store refresh token if needed

VII. **Response Formation**
   - Return success message with user info
   - Include tokens if email verification not required
   - Return verification message if email verification required

### Libraries Used
- `bcrypt` for password hashing
- `@nestjs/jwt` for token generation
- `nodemailer` for email verification
- `class-validator` for input validation

---

## 3. Login/Signup with Google API

### Controller Function Arguments
- `code`: string (authorization code from Google)
- `state`: string (optional, for CSRF protection)

### Step-by-Step Logic Flow
I. **Google OAuth Verification**
   - Use passport-google-oauth20 strategy
   - Exchange authorization code for access token
   - Retrieve user profile from Google API

II. **Profile Data Extraction**
   - Extract email, firstName, lastName from Google profile
   - Verify email is verified on Google side
   - Get Google user ID for future reference

III. **User Existence Check**
   - Query database for user with Google ID or email
   - Handle three scenarios: new user, existing user with Google, existing user without Google

IV. **User Creation/Update Logic**
   - **New User**: Create account with Google profile data
   - **Existing Google User**: Update profile if needed
   - **Existing Email User**: Link Google account to existing user

V. **Account Linking** (if applicable)
   - If email exists but no Google link, prompt for password confirmation
   - Link Google account to existing user account
   - Update user record with Google ID

VI. **JWT Token Generation**
   - Create JWT payload with user info
   - Generate access and refresh tokens
   - Mark account as verified (since Google verified email)

VII. **Response Formation**
   - Return tokens and user info
   - Include account linking status if applicable

### Libraries Used
- `passport-google-oauth20` for Google OAuth
- `@nestjs/passport` for passport integration
- `@nestjs/jwt` for token generation

---

## 4. Login/Signup with GitHub API

### Controller Function Arguments
- `code`: string (authorization code from GitHub)
- `state`: string (optional, for CSRF protection)

### Step-by-Step Logic Flow
I. **GitHub OAuth Verification**
   - Use passport-github2 strategy
   - Exchange authorization code for access token
   - Retrieve user profile from GitHub API

II. **Profile Data Extraction**
   - Extract username, email, name from GitHub profile
   - Handle cases where email might be private
   - Get GitHub user ID for future reference

III. **Email Handling**
   - If email is private, fetch from GitHub API with proper scopes
   - If still unavailable, prompt user to provide email

IV. **User Existence Check**
   - Query database for user with GitHub ID or email
   - Handle multiple scenarios like Google OAuth

V. **User Creation/Update Logic**
   - **New User**: Create account with GitHub profile data
   - **Existing GitHub User**: Update profile if needed
   - **Existing Email User**: Link GitHub account

VI. **Account Verification**
   - Mark email as verified if it's verified on GitHub
   - Set appropriate account status

VII. **JWT Token Generation**
   - Create JWT payload with user info
   - Generate access and refresh tokens

VIII. **Response Formation**
   - Return tokens and user info
   - Include account linking status

### Libraries Used
- `passport-github2` for GitHub OAuth
- `@nestjs/passport` for passport integration
- `@nestjs/jwt` for token generation

---

## 5. Forget Password API

### Controller Function Arguments
- `email`: string (required)

### Step-by-Step Logic Flow
I. **Input Validation**
   - Validate email format
   - Check if email is provided

II. **User Existence Check**
   - Query database to find user by email
   - If user doesn't exist, return success (security: don't reveal user existence)

III. **Rate Limiting Check**
   - Check if user has requested password reset recently
   - Prevent spam by limiting requests (e.g., 1 per 15 minutes)

IV. **Reset Token Generation**
   - Generate cryptographically secure random token
   - Set token expiration (typically 1 hour)
   - Store token hash in database with user ID

V. **Email Preparation**
   - Create password reset email with token link
   - Include expiration time and security instructions
   - Use professional email template

VI. **Email Sending**
   - Send email using nodemailer
   - Handle email sending failures gracefully
   - Log email sending attempts

VII. **Response Formation**
   - Always return success message (security practice)
   - Don't reveal whether email exists or not

### Libraries Used
- `nodemailer` for email sending
- `crypto` (Node.js built-in) for token generation
- `class-validator` for input validation

---

## 6. Reset Password API

### Controller Function Arguments
- `token`: string (reset token from email)
- `newPassword`: string (required)
- `confirmPassword`: string (required)

### Step-by-Step Logic Flow
I. **Input Validation**
   - Validate token format
   - Check password strength requirements
   - Verify newPassword and confirmPassword match

II. **Token Verification**
   - Query database for valid, non-expired token
   - If token is invalid/expired, return BadRequestException
   - Check if token hasn't been used already

III. **User Identification**
   - Get user associated with the reset token
   - Verify user account is still active

IV. **Password Security Check**
   - Ensure new password is different from current password
   - Check against password history if implemented

V. **Password Update**
   - Hash new password using bcrypt
   - Update user's password in database
   - Mark reset token as used/expired

VI. **Security Cleanup**
   - Invalidate all existing refresh tokens for user
   - Log password change event
   - Clear any active sessions

VII. **Notification**
   - Send password change confirmation email
   - Include security tips and monitoring advice

VIII. **Response Formation**
   - Return success message
   - Optionally return new JWT tokens for immediate login

### Libraries Used
- `bcrypt` for password hashing
- `@nestjs/jwt` for token generation
- `nodemailer` for confirmation email

---

## 7. Reset Token API (Refresh Token)

### Controller Function Arguments
- `refreshToken`: string (required, from cookie or header)

### Step-by-Step Logic Flow
I. **Token Extraction**
   - Extract refresh token from HTTP-only cookie or Authorization header
   - Validate token format and presence

II. **Token Verification**
   - Verify refresh token signature using JWT
   - Check if token is expired
   - Validate token structure and required claims

III. **Token Blacklist Check**
   - Query database to check if token is blacklisted
   - If blacklisted, return UnauthorizedException

IV. **User Verification**
   - Extract user ID from token payload
   - Query database to verify user still exists and is active
   - Check if user hasn't been banned/deactivated

V. **Token Rotation** (Security Best Practice)
   - Generate new access token with fresh expiration
   - Generate new refresh token (optional, for better security)
   - Blacklist old refresh token if rotating

VI. **Session Update**
   - Update last activity timestamp
   - Log token refresh event
   - Update any session-related data

VII. **Response Formation**
   - Return new access token
   - Return new refresh token if rotated
   - Include token expiration times

### Libraries Used
- `@nestjs/jwt` for token verification and generation
- Database for token blacklisting
- `class-validator` for input validation

---

## Additional Security Considerations

### Rate Limiting
- Implement rate limiting on all authentication endpoints
- Use different limits for different operations (login vs. password reset)

### CORS Configuration
- Configure CORS properly for frontend applications
- Restrict origins in production

### Input Sanitization
- Sanitize all inputs to prevent injection attacks
- Use class-transformer for data transformation

### Logging and Monitoring
- Log all authentication attempts (success and failure)
- Monitor for suspicious activities
- Implement alerting for multiple failed attempts

### Environment Variables
- Store secrets in environment variables
- Use different configurations for development/production

### Database Security
- Use parameterized queries to prevent SQL injection
- Implement proper indexing for performance
- Regular security audits of user data

### Token Security
- Use HTTP-only cookies for refresh tokens when possible
- Implement proper token expiration strategies
- Consider token rotation for enhanced security