# Testing with Real LDAP

This guide explains how to test fastapi-ldap with a real LDAP server using Docker.

## Quick Start

### Option 1: Using Docker Compose (Recommended)

1. **Start the LDAP server and setup test data:**
   ```bash
   chmod +x docker-ldap-setup.sh
   ./docker-ldap-setup.sh
   ```

2. **Run the example application:**
   ```bash
   poetry run python example-docker.py
   ```

3. **Test the API:**
   ```bash
   # Test authentication (use Basic Auth)
   curl -u testuser:testpass123 http://localhost:8000/protected
   
   # Test admin endpoint
   curl -u adminuser:adminpass123 http://localhost:8000/admin
   ```

### Option 2: Manual Docker Setup

1. **Start LDAP server:**
   ```bash
   docker-compose up -d ldap
   ```

2. **Wait for LDAP to be ready:**
   ```bash
   docker exec fastapi-ldap-openldap ldapsearch -x -H ldap://localhost:389 \
     -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w admin
   ```

3. **Create test users manually** (see docker-ldap-setup.sh for examples)

## Test Credentials

After running `docker-ldap-setup.sh`, you'll have:

- **testuser** / testpass123 (member of "users" group)
- **adminuser** / adminpass123 (member of "users" and "admins" groups)

## LDAP Configuration

The Docker setup creates:

- **Base DN:** `dc=example,dc=com`
- **Users OU:** `ou=users,dc=example,dc=com`
- **Groups OU:** `ou=groups,dc=example,dc=com`
- **Admin DN:** `cn=admin,dc=example,dc=com`
- **Admin Password:** `admin`

## Alternative LDAP Servers

### Apache Directory Studio (Docker)

```bash
docker run -d \
  --name apache-ds \
  -p 10389:10389 \
  -p 10636:10636 \
  apacheds/apacheds:latest
```

Default credentials:
- Admin DN: `uid=admin,ou=system`
- Password: `secret`

### FreeIPA (Full-featured, more complex)

```bash
docker run -d \
  --name freeipa \
  -h ipa.example.test \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  --tmpfs /run \
  --tmpfs /tmp \
  -e IPA_SERVER_IP=127.0.0.1 \
  -p 80:80 -p 443:443 -p 389:389 -p 636:636 \
  freeipa/freeipa-server:latest
```

### Active Directory (Windows Container)

For testing with Active Directory, you can use:

```bash
docker run -d \
  --name ad \
  -p 389:389 -p 636:636 \
  -e DOMAIN=example.com \
  -e ADMIN_PASSWORD=Admin123! \
  dinkel/openldap:latest
```

## Testing with TLS/SSL

To test with TLS:

1. **Update docker-compose.yml** to enable TLS properly
2. **Use ldaps://** in your configuration:
   ```python
   settings = LDAPSettings(
       ldap_url="ldaps://localhost:636",
       use_tls=True,
       tls_require_cert=False,  # Set to True in production
       # ... other settings
   )
   ```

## phpLDAPadmin Web Interface

The docker-compose setup includes phpLDAPadmin for easy LDAP management:

- **URL:** http://localhost:8080
- **Login DN:** `cn=admin,dc=example,dc=com`
- **Password:** `admin`

## Troubleshooting

### LDAP connection fails

1. Check if container is running:
   ```bash
   docker ps | grep ldap
   ```

2. Check LDAP logs:
   ```bash
   docker logs fastapi-ldap-openldap
   ```

3. Test LDAP connection:
   ```bash
   docker exec fastapi-ldap-openldap ldapsearch -x -H ldap://localhost:389 \
     -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w admin
   ```

### Authentication fails

1. Verify user exists:
   ```bash
   docker exec fastapi-ldap-openldap ldapsearch -x -H ldap://localhost:389 \
     -b "ou=users,dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w admin \
     "(uid=testuser)"
   ```

2. Check user password:
   ```bash
   docker exec fastapi-ldap-openldap ldapwhoami -x -H ldap://localhost:389 \
     -D "uid=testuser,ou=users,dc=example,dc=com" -w testpass123
   ```

### Group membership not working

1. Check group membership:
   ```bash
   docker exec fastapi-ldap-openldap ldapsearch -x -H ldap://localhost:389 \
     -b "ou=groups,dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w admin \
     "(memberUid=testuser)"
   ```

## Cleanup

To stop and remove containers:

```bash
docker-compose down -v
```

This will remove containers and volumes (all data will be lost).

## Production Considerations

⚠️ **Warning:** The Docker setup is for **testing only**. For production:

1. Use proper TLS certificates
2. Set strong passwords
3. Use proper LDAP schema
4. Configure proper access controls
5. Use LDAPS (ldaps://) with valid certificates
6. Set `tls_require_cert=True` in production

