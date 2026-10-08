import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-audit',
  standalone: true,
  imports: [CommonModule],
  template: `
  <span class="eyebrow">APPEND-ONLY · SHA-256 CHAINED</span>
  <h1 class="hero-title">Audit log, <em>tamper-evident.</em></h1>
  <p class="muted">Append-only · each entry hashes the previous (<span class="mono">SHA-256(seq|actor|action|details|prev|ts)</span>). Edit anything → chain breaks.</p>
  <div class="card">
    <button class="primary" (click)="verify()">✔ Verify chain now</button>
    <span *ngIf="verdict" class="badge" [class.ok]="verdict.ok" [class.bad]="!verdict.ok" style="margin-left:10px">
      {{verdict.ok ? '✔ INTACT · '+verdict.checked+' entries · head '+verdict.head?.slice(0,16)+'…' : '✖ BROKEN at seq '+verdict.broken_at_seq}}</span>
  </div>
  <div class="card"><table><tr><th>#</th><th>Actor</th><th>Action</th><th>Details</th><th>Hash</th><th>Time</th></tr>
    <tr *ngFor="let a of rows()"><td>{{a.seq}}</td><td class="mono">{{a.actor}}</td><td><span class="badge">{{a.action}}</span></td>
    <td class="mono">{{a.details}}</td><td class="mono">{{a.entry_hash?.slice(0,12)}}…</td><td class="muted">{{a.created_at|date:'short'}}</td></tr></table>
  </div>`,
})
export class AuditComponent implements OnInit {
  private api = inject(ApiService);
  rows = signal<any[]>([]);
  verdict: any = null;
  ngOnInit() { this.refresh(); }
  refresh() { this.api.audit().subscribe({ next: (r) => this.rows.set(r) }); }
  verify() { this.api.auditVerify().subscribe({ next: (v) => (this.verdict = v) }); }
}
