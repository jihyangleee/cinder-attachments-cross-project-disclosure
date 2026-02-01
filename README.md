# OpenStack Cinder Attachments
## Cross-Project Metadata Disclosure (Authorization Bypass)

**Related Launchpad Bug**  
https://bugs.launchpad.net/cinder/+bug/2138566

---

## Impact
OpenStack Cinder의 Attachments API는 인증된 사용자가  
다른 프로젝트(Project)에 속한 attachment의 `connection_info`를 조회할 수 있도록 허용합니다.

이로 인해 멀티 테넌트 환경에서 테넌트 간 정보 노출(cross-tenant information disclosure)이 발생하며,  
이는 OpenStack의 테넌트 격리(tenant isolation) 보안 모델을 위반합니다.

스토리지 백엔드 구성에 따라 다음과 같은 정보가 노출될 수 있습니다.

- 스토리지 백엔드 타깃 주소
- Export 경로
- 인증 파라미터
- 프로토콜별 설정 정보 (iSCSI, Ceph 등)

---

## Executive Summary
Attachments API에서는 인가(Authorization) 검증과  
프로젝트 범위(Project Scope) 검사가 누락되어 있습니다.

그 결과 일반 권한(member-level)을 가진 사용자도  
다른 프로젝트에 속한 attachment의 메타데이터를 조회할 수 있습니다.

API는 리소스 소유권을 검증하지 않은 채  
민감한 스토리지 백엔드 연결 정보(`connection_info`)를 그대로 반환합니다.

---

## Affected Product / Versions
- Component: OpenStack Cinder
- Tested Version: Cinder 27.1.0 (master)
- Deployment: Kolla-Ansible (Ubuntu Noble)
- Likely Affected:  
  Attachments API에서 프로젝트 단위 인가를 강제하지 않는 모든 Cinder 버전

---

## Vulnerability Classification
- CWE-284: Improper Access Control
- CWE-200: Exposure of Sensitive Information

---

## Root Cause Analysis

### 프로젝트 범위 강제 미적용
Attachments API는 attachment 객체 조회 시  
API 레벨에서 프로젝트 단위 제한(project-only scoping)을 적용하지 않습니다.

DB 레벨에서는 `project_only` 옵션이 존재하지만  
해당 옵션이 사용되지 않아 프로젝트 간 접근이 가능합니다.

---

### 민감 필드 노출 (`connection_info`)
API 응답에는 attachment의 연결 정보가 그대로 포함됩니다.

```python
connection_info = attachment.connection_info
```

## Proof of Concept

### 시나리오
1. Project A의 일반 사용자(Member)가 Project B에 속한 특정 Attachment ID를 알고 있음.

2. 공격자는 유효한 인증 토큰을 보유하고 있음.

3. Attachments API에 직접 요청을 전송함.

4. 보안 검증 부재로 인해 Project B의 connection_info를 획득함.

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

본 취약점은 OpenStack의 멀티 테넌트 보안 모델을 약화시키며,
스토리지 백엔드 구성에 따라 더 심각한 2차 공격으로 확장될 수 있습니다.
---

## Mitigations

### API 레벨 인가 검증 적용
- 모든 attachment 조회 경로에서 context.authorize() 호출
- 프로젝트 단위 접근 제어 정책 강제
- Snapshots / Volumes API와 동일한 권한 모델 적용

### DB 레벨 프로젝트 범위 필터링 적용
- Attachment 조회 시 project_only=True 명시적으로 적용
- 항상 context.project_id 기준으로 필터링

### 민감 정보 노출 제한
- 일반 사용자에게는 connection_info 필드 마스킹 또는 제거
- 시스템 레벨 작업에서만 제한적으로 노출

### 정책 일관성 유지
- Attachments API를 Snapshots / Volumes API와 동일한 접근 제어 모델로 정렬
- 스토리지 API 전반에서 일관된 테넌트 격리 보장
---

## Conclusion
본 취약점은 단일 API에서의 인가 검증 누락과
프로젝트 범위 제한 미적용이
OpenStack의 테넌트(project) 격리 모델 전체를 훼손할 수 있음을 보여줍니다.

API 및 DB 레벨에서의 엄격한 접근 제어 적용과
민감 정보 노출 최소화를 통해
프로젝트 간 메타데이터 노출 위험을 효과적으로 완화할 수 있습니다.
