# White Label Voucher Management System

A comprehensive voucher management system with Pretix integration and SSO support for events, businesses, and organizations.

## Features

**White Label Design**
- Fully customizable branding with your logo and company name
- Clean, modern interface with responsive design
- No visible third-party branding

**Voucher Management**
- Create, manage, and track vouchers
- Multiple voucher types (Food, Drink, Merchandise, General)
- Bulk voucher creation and management
- QR code generation for scanning
- Real-time status tracking

**Pretix Integration**
- Seamless synchronization with Pretix ticketing system
- Automatic voucher creation and deletion
- Bidirectional sync for user management
- Bulk operations with Pretix sync

**Single Sign-On (SSO)**
- OpenID Connect (OIDC) support
- Works with Keycloak, Auth0, and other OIDC providers
- Automatic user provisioning
- Secure authentication flow

**User Management**
- Role-based access control (Admin, User Manager, Voucher Manager, Scanner, User)
- User activation/deactivation with automatic voucher handling
- Password management and user search

**Admin Dashboard**
- Real-time statistics and analytics
- User activity monitoring
- System configuration and integration management

## Installation

### Prerequisites
- PHP 8.0 or higher
- MySQL 5.7 or higher
- Web server (Apache/Nginx)

### Quick Setup

1. **Clone and upload**
   ```bash
   git clone https://github.com/yourusername/voucher-system.git
   ```

2. **Run installation wizard**
   - Navigate to `https://yourdomain.com/install.php`
   - Complete 8-step setup process

3. **Security**
   ```bash
   rm install.php
   ```

### Configuration Steps
1. Database Configuration
2. Database Setup
3. Admin User Creation
4. Application Configuration
5. Logo & Branding
6. Pretix Integration (optional)
7. SSO Configuration (optional)
8. Installation Complete

## Usage

**End Users**
- Login via username/password or SSO
- View and redeem assigned vouchers
- QR code scanning support

**Administrators**
- Manage users and voucher types
- Monitor system statistics
- Configure integrations

**Voucher Managers**
- Create and manage voucher categories
- Bulk operations and data export

## System Requirements

**Minimum:**
- PHP 8.0+, MySQL 5.7+
- 512MB RAM, 100MB disk space

**Recommended:**
- PHP 8.2+, MySQL 8.0+
- 1GB RAM, 500MB disk space
- SSL certificate

## Security Features

- Password hashing with secure algorithms
- SQL injection prevention
- CSRF protection
- Session security
- Role-based access control

## License

MIT License - see LICENSE file for details.

## Support

- Report bugs via GitHub Issues
- Check wiki for documentation
- Join community discussions

Transform your voucher operations with a professional, scalable solution.
