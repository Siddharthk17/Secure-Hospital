import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-compose',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
  <span class="eyebrow">OUTBOUND · SEALED ENVELOPE V1</span>
  <h1 class="hero-title">Seal & send <em>in one atomic call.</em></h1>
  <p class="hero-sub">Canonicalise → hash → fresh DEK+IV → AES-GCM → OAEP-wrap → PSS-sign → store <b>ciphertext only</b>.</p>
  <div class="grid2">
    <div class="card">
      <label>Patient MRN <input [(ngModel)]="mrn" placeholder="MRN-1001" /></label>
      <label>Recipient username <input [(ngModel)]="to" placeholder="dr_rohan" /></label>
      <label>Subject <input [(ngModel)]="subject" placeholder="ECG + Troponin review" /></label>
      <label>Clinical body <textarea [(ngModel)]="body" placeholder="Findings, dosage, next steps…"></textarea></label>
      <button class="primary" (click)="send()" [disabled]="busy">{{busy?'Sealing…':'🔒 Seal & send'}}</button>
      <div *ngIf="error" class="alert bad">{{error}}</div>
      <div *ngIf="done" class="alert ok">
        Sealed & delivered. Digest <span class="mono">{{done.digest_hex?.slice(0,24)}}…</span>
        · report <span class="mono">{{done.id}}</span> · status <b>{{done.status}}</b>
      </div>
    </div>
    <div class="card steps">
      <h2>What the server does (auditable)</h2>
      <ol>
        <li>Loads <b>recipient's RSA-OAEP public key</b> + your <b>RSA-PSS signing key</b> (+CA cert check).</li>
        <li>Builds canonical JSON incl. <span class="mono">timestamp + nonce + msg_id</span> (replay binding).</li>
        <li><span class="mono">SHA-256 → AES-256-GCM(DEK, iv, aad) → OAEP(DEK) → PSS(digest)</span>.</li>
        <li>Stores envelope only; appends <span class="mono">REPORT_SEAL_SEND</span> to the hash-chained audit log.</li>
      </ol>
      <h3>Known staff</h3>
      <table><tr><th>User</th><th>Dept</th><th>Fingerprint</th></tr>
      <tr *ngFor="let u of staff()"><td class="mono">{{u.username}}</td><td>{{u.department}}</td><td class="mono">{{u.key_fingerprint}}</td></tr></table>
    </div>
  </div>`,
})
export class ComposeComponent implements OnInit {
  private api = inject(ApiService);
  mrn = 'MRN-1001'; to = 'dr_rohan'; subject = 'ECG review — Aarav Sharma'; body = 'Sinus rhythm, HR 72. Troponin negative. Continue aspirin 75mg OD. Review in 2 weeks.';
  busy = false; error = ''; done: any = null;
  staff = signal<any[]>([]);
  ngOnInit() { this.api.users().subscribe({ next: (u) => this.staff.set(u) }); }
  send() {
    this.busy = true; this.error = ''; this.done = null;
    this.api.sendReport({ patient_mrn: this.mrn, recipient_username: this.to, subject: this.subject, body: this.body }).subscribe({
      next: (r) => { this.done = r; this.busy = false; },
      error: (e) => { this.error = e?.error?.detail || JSON.stringify(e?.error || e); this.busy = false; },
    });
  }
}
