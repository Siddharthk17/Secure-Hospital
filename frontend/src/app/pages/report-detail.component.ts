import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-report-detail',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
  <a routerLink="/inbox">← back</a>
  <span class="eyebrow" style="margin-left:12px">SEALED ENVELOPE · OPEN + VERIFY</span>
  <div *ngIf="loading" class="card">Decrypting & verifying…</div>
  <div *ngIf="denied" class="card"><div class="alert bad">{{denied}}</div>
    <div class="kv" *ngIf="meta"><b>Subject</b><span>{{meta.subject}}</span><b>Status</b><span>{{meta.status}}</span></div>
  </div>
  <div *ngIf="data" class="card">
    <h1>{{data.report?.subject || 'Report'}} <span class="badge ok" *ngIf="data.status==='OPENED'">✔ VERIFIED</span></h1>
    <div class="kv">
      <b>Patient</b><span>{{data.report?.patient_name}} (<span class="mono">{{data.report?.patient_mrn}}</span>)</span>
      <b>From → To</b><span class="mono">{{data.report?.sender}} → {{data.report?.recipient}}</span>
      <b>Timestamp</b><span>{{data.report?.timestamp}}</span>
      <b>SHA-256</b><span class="mono">{{data.digest_hex}}</span>
    </div>
    <h3>Clinical body (decrypted for recipient only)</h3>
    <div class="card" style="background:#0a1326">{{data.report?.body}}</div>
    <h3>Triple verification</h3>
    <table><tr><th>Check</th><th>Result</th><th>What it proves</th></tr>
      <tr><td>AES-GCM tag</td><td><span class="badge" [class.ok]="data.verification.gcm_tag_ok" [class.bad]="!data.verification.gcm_tag_ok">{{data.verification.gcm_tag_ok?'PASS':'FAIL'}}</span></td><td>Ciphertext untouched in transit</td></tr>
      <tr><td>SHA-256 digest</td><td><span class="badge" [class.ok]="data.verification.hash_ok" [class.bad]="!data.verification.hash_ok">{{data.verification.hash_ok?'PASS':'FAIL'}}</span></td><td>Plaintext identical to what was sealed</td></tr>
      <tr><td>RSA-PSS signature</td><td><span class="badge" [class.ok]="data.verification.signature_ok" [class.bad]="!data.verification.signature_ok">{{data.verification.signature_ok?'PASS':'FAIL'}}</span></td><td>Sealed by the claimed sender (non-repudiation)</td></tr>
      <tr><td>CA certificate</td><td><span class="badge" [class.ok]="data.verification.ca_cert_valid" [class.bad]="!data.verification.ca_cert_valid">{{data.verification.ca_cert_valid?'VALID':'INVALID'}}</span></td><td>Sender key truly belongs to sender</td></tr>
    </table>
  </div>
  <div *ngIf="tamper" class="card"><div class="alert bad">⛔ {{tamper.error || 'Integrity/authenticity check failed — quarantined.'}}</div>
    <table><tr><th>Check</th><th>Result</th></tr>
    <tr><td>GCM</td><td>{{tamper.verification.gcm_tag_ok}}</td></tr>
    <tr><td>Hash</td><td>{{tamper.verification.hash_ok}}</td></tr>
    <tr><td>Signature</td><td>{{tamper.verification.signature_ok}}</td></tr></table>
  </div>
  <div *ngIf="audit" class="card"><h2>Sender-side proof (no decryption needed)</h2><div class="kv">
    <b>Signature valid</b><span>{{audit.signature_ok}}</span><b>Sender key</b><span class="mono">{{audit.sender_fingerprint}}</span>
  </div></div>`,
})
export class ReportDetailComponent implements OnInit {
  private route = inject(ActivatedRoute);
  private api = inject(ApiService);
  loading = true; data: any = null; tamper: any = null; denied = ''; meta: any = null; audit: any = null;
  ngOnInit() {
    const id = this.route.snapshot.paramMap.get('id')!;
    this.api.openReport(id).subscribe({
      next: (r: any) => { this.loading = false; this.data = r; },
      error: (e) => {
        this.loading = false;
        if (e.status === 409) this.tamper = e.error;
        else if (e.status === 200 && e.error?.meta) { this.meta = e.error.meta; this.denied = e.error.detail; this.loadAudit(id); }
        else if (e.status === 403) { this.denied = e.error?.detail; }
        else this.denied = 'Load failed: ' + JSON.stringify(e?.error || e);
      },
    });
  }
  loadAudit(id: string) { this.api.verifyOnly(id).subscribe({ next: (r) => (this.audit = r) }); }
}
