# OpenStack Cinder Attachments  
## Cross-Project Metadata Disclosure (Authorization Bypass)

### Executive Summary
OpenStack **Cinder attachments API**에서 프로젝트 범위 검증과 정책 체크가 누락되어,  
**다른 프로젝트에 속한 attachment의 `connection_info`를 조회할 수 있는 취약점**이 존재합니다.

이로 인해 멀티 테넌트 환경에서 **스토리지 백엔드 정보가 교차 노출**되며,  
후속 공격(무단 스토리지 접근, 데이터 유출 등)으로 이어질 수 있습니다.

---

### Affected Product / Versions
- **Component**: OpenStack Cinder
- **Tested Version**: Cinder 27.1.0 (master)
- **Likely Affected**:  
  Attachments API에서 project-scoped authorization을 강제하지 않는 모든 버전

---

### Vulnerability Classification
- **CWE-284**: Improper Access Control  
- **CWE-200**: Exposure of Sensitive Information

---

### Root Cause Overview
- Attachments API에서 `context.authorize()` 호출 누락
- API 레벨에서 정책(policy) 검증 부재
- DB 조회 시 `project_only` 스코프 미적용
- `connection_info`가 마스킹 없이 그대로 반환됨

---

### Technical Details

#### 1. Missing API Authorization
- Snapshots / Volumes API와 달리 attachments API에는  
  `SYSTEM_READER_OR_PROJECT_READER` 수준의 정책 검증이 없음
- 요청자가 attachment 리소스의 소유 프로젝트인지 검증하지 않음

#### 2. Missing Project Scope Enforcement
- Attachment 조회 시 DB 쿼리에 `project_only=True`가 적용되지 않음
- Attachment ID만 알고 있으면 cross-project 접근 가능

#### 3. Sensitive Field Exposure
- `attachment.connection_info`가 API 응답에 그대로 포함됨
- NFS뿐 아니라 iSCSI, Ceph 환경에서는 자격증명 노출 위험이 더 큼

---

### Proof of Concept (High-Level)

**Scenario**
- Project A의 일반 사용자(member)가
- Project B의 attachment ID를 이용해
- Attachments API를 직접 호출
- → Project B의 `connection_info` 획득

**Attack Vector**
```bash
curl -X GET \
  http://<cinder-api>:8776/v3/attachments/<attachment_id> \
  -H "X-Auth-Token: <user-token>" \
  -H "OpenStack-API-Version: volume 3.27"
