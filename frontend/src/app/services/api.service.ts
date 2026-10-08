import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);

  me() { return this.http.get<any>('/api/me/'); }
  users() { return this.http.get<any[]>('/api/users/'); }
  securityOverview() { return this.http.get<any>('/api/system/security-overview/'); }
  patients() { return this.http.get<any[]>('/api/patients/'); }
  addPatient(p: any) { return this.http.post('/api/patients/', p); }
  sendReport(r: any) { return this.http.post<any>('/api/reports/send/', r); }
  inbox() { return this.http.get<any[]>('/api/reports/inbox/'); }
  sent() { return this.http.get<any[]>('/api/reports/sent/'); }
  search(q: string) { return this.http.get<any[]>(`/api/reports/search/?q=${encodeURIComponent(q)}`); }
  openReport(id: string) { return this.http.get<any>(`/api/reports/${id}/open/`); }
  verifyOnly(id: string) { return this.http.get<any>(`/api/reports/${id}/verify/`); }
  attack(id: string, mode: string) { return this.http.post<any>(`/api/lab/attacker/${id}/`, { mode }); }
  audit() { return this.http.get<any[]>('/api/audit/'); }
  auditVerify() { return this.http.get<any>('/api/audit/verify/'); }
  rotateKeys() { return this.http.post<any>('/api/keys/rotate/', {}); }
  register(u: any) { return this.http.post<any>('/api/auth/register/', u); }
}
