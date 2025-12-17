#!/bin/bash
# Setup script for testing fastapi-ldap with OpenLDAP Docker container

set -e

echo "Setting up OpenLDAP for fastapi-ldap testing..."

echo "Starting OpenLDAP container..."
docker-compose up -d ldap

echo "Waiting for LDAP server to be ready..."
sleep 10

max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if docker exec fastapi-ldap-openldap ldapsearch -x -H ldap://localhost:389 -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w admin > /dev/null 2>&1; then
        echo "✅ LDAP server is ready!"
        break
    fi
    attempt=$((attempt + 1))
    echo "   Attempt $attempt/$max_attempts..."
    sleep 2
done

if [ $attempt -eq $max_attempts ]; then
    echo "❌ LDAP server failed to start"
    exit 1
fi

echo "👤 Creating test users and groups..."

docker exec fastapi-ldap-openldap ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin <<EOF
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
ou: users
EOF

docker exec fastapi-ldap-openldap ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin <<EOF
dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
ou: groups
EOF

docker exec fastapi-ldap-openldap ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin <<EOF
dn: uid=testuser,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: testuser
sn: User
givenName: Test
cn: Test User
displayName: Test User
uidNumber: 1000
gidNumber: 1000
userPassword: testpass123
mail: testuser@example.com
homeDirectory: /home/testuser
EOF

# Create test user: adminuser
docker exec fastapi-ldap-openldap ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin <<EOF
dn: uid=adminuser,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: adminuser
sn: Admin
givenName: Admin
cn: Admin User
displayName: Admin User
uidNumber: 1001
gidNumber: 1001
userPassword: adminpass123
mail: adminuser@example.com
homeDirectory: /home/adminuser
EOF

# Create group: users
docker exec fastapi-ldap-openldap ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin <<EOF
dn: cn=users,ou=groups,dc=example,dc=com
objectClass: posixGroup
cn: users
gidNumber: 1000
memberUid: testuser
memberUid: adminuser
EOF

# Create group: admins
docker exec fastapi-ldap-openldap ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin <<EOF
dn: cn=admins,ou=groups,dc=example,dc=com
objectClass: posixGroup
cn: admins
gidNumber: 1001
memberUid: adminuser
EOF

echo ""
echo "✅ Setup complete!"
echo ""
echo "Test Credentials:"
echo "   User: testuser / Password: testpass123"
echo "   User: adminuser / Password: adminpass123"
echo ""
echo "🔧 LDAP Configuration for example.py:"
echo "   LDAP_URL=ldap://localhost:389"
echo "   LDAP_BASE_DN=dc=example,dc=com"
echo "   LDAP_BIND_DN=cn=admin,dc=example,dc=com"
echo "   LDAP_BIND_PASSWORD=admin"
echo "   LDAP_USER_SEARCH_FILTER=(uid={username})"
echo "   LDAP_USER_SEARCH_BASE=ou=users,dc=example,dc=com"
echo "   LDAP_GROUP_SEARCH_FILTER=(memberUid={username})"
echo "   LDAP_GROUP_SEARCH_BASE=ou=groups,dc=example,dc=com"
echo ""
echo "🌐 phpLDAPadmin available at: http://localhost:8080"
echo "   Login DN: cn=admin,dc=example,dc=com"
echo "   Password: admin"
echo ""
echo "To stop: docker-compose down"

