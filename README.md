# OpenStack Cinder Attachments
## Cross-Project Metadata Disclosure (Authorization Bypass)

## Impact
The OpenStack Cinder attachments API allows an authenticated user to retrieve  
\`connection_info\` belonging to attachments owned by **other projects**.

This results in **cross-tenant information disclosure**, violating OpenStack’s  
tenant isolation guarantees in multi-tenant environments.

Depending on the storage backend in use, the exposed information may include:
- Backend target addresses
- Export paths
- Authentication parameters
- Protocol-specific configuration details (e.g., iSCSI, Ceph)

While the demonstrated Proof of Concept uses an NFS backend and does not  
immediately result in host compromise, the disclosed information can  
**enable follow-up attacks**, including:
- Unauthorized storage access
- Data exfiltration
- Further lateral movement within the infrastructure

---

## Executive Summary
Due to missing authorization enforcement and insufficient project scope  
validation in the OpenStack Cinder attachments API, a member-level user can  
access attachment metadata belonging to another project.

The API returns sensitive backend storage connection details  
(\`connection_info\`) without verifying resource ownership or enforcing  
project-scoped access control.

This behavior is inconsistent with other volume-related APIs (e.g., snapshots,  
volumes) and represents a meaningful security risk in multi-tenant OpenStack  
deployments.

---

## Affected Product / Versions
- **Component**: OpenStack Cinder
- **Tested Version**: Cinder 27.1.0 (master branch)
- **Deployment**: Kolla-Ansible (Ubuntu Noble)
- **Likely Affected**:  
  All Cinder versions where the attachments API does not enforce  
  project-scoped authorization checks when retrieving attachment details

---

## Vulnerability Classification
- **CWE-284**: Improper Access Control  
- **CWE-200**: Exposure of Sensitive Information

---

## Root Cause Overview
The vulnerability is caused by a combination of missing authorization checks  
and insufficient project scope enforcement across multiple layers:

- Attachments API does not invoke \`context.authorize()\`
- No policy rules are enforced to validate resource ownership
- Database queries retrieving attachment objects do not consistently apply  
  project scoping
- Sensitive backend information (\`connection_info\`) is returned without  
  masking or sanitization

---

## Technical Details

### Missing API-Level Authorization
Unlike other volume-related APIs such as snapshots and volumes, the attachments  
API does not enforce policies equivalent to  
\`SYSTEM_READER_OR_PROJECT_READER\`.

As a result:
- No policy checks verify whether the requesting user is authorized to access  
  the specified attachment
- Any authenticated user with a valid token can query attachment details  
  if the attachment ID is known

---

### Missing Project Scope Enforcement
The attachments API retrieves attachment objects without enforcing  
project-only scoping at the API layer.

Although the database layer supports project-scoped filtering through the  
\`project_only\` parameter, this parameter is not applied when retrieving  
attachments, enabling cross-project access to attachment metadata.

---

### Sensitive Field Exposure (\`connection_info\`)
The API response directly includes:

\`\`\`python
connection_info = attachment.connection_info
\`\`\`

without any masking, sanitization, or authorization-based filtering.

---

## Proof of Concept

### Scenario
A member-level user in **Project A** is able to retrieve the  
\`connection_info\` of an attachment belonging to **Project B** by sending a  
direct request to the attachments API using a known attachment ID.

---

### Attack Vector
\`\`\`bash
TOKEN=\$(openstack token issue -f value -c id)

curl -X GET \\
  http://<cinder-api>:8776/v3/attachments/<attachment_id> \\
  -H "X-Auth-Token: \$TOKEN" \\
  -H "OpenStack-API-Version: volume 3.27"
\`\`\`

---

## Security Impact Assessment
- **Impact**: High  
- **Attack Complexity**: Low  
- **Privileges Required**: Authenticated user (member role)  
- **Scope**: Changed (cross-project access)

---

## Mitigations

### Enforce Policy Checks in Attachments API
- Invoke \`context.authorize()\` in all attachment retrieval paths
- Enforce project-scoped access rules
- Align required roles with snapshot and volume APIs

### Apply Project-Scoped Filtering at Database Layer
- Explicitly apply \`project_only=True\`
- Ensure attachment queries are filtered by \`context.project_id\`

### Restrict Exposure of Sensitive Fields
- Mask or remove \`connection_info\` for non-system users
- Only expose backend details to authorized system-level operations

### Align Attachment Access Policies
- Use the same authorization model as snapshots and volumes APIs

---

## Conclusion
This vulnerability demonstrates how missing authorization checks and  
insufficient project scope enforcement in a single API can undermine  
OpenStack’s tenant isolation model.

By enforcing consistent access control policies, applying strict project  
scoping, and limiting sensitive backend information exposure, the risk of  
cross-project metadata disclosure can be effectively mitigated.
EOF
