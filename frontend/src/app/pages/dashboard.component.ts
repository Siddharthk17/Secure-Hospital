import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiService } from '../services/api.service';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
  <span class="eyebrow">SIGNED IN AS {{auth.username().toUpperCase()}}</span>
  <h1 class="hero-title">Good shift, {{auth.username()}}. <em>Zero-trust rounds.</em></h1>
  <p class="hero-sub">Sealed-envelope pipeline: <b>canonical JSON → SHA-256 → AES-256-GCM → RSA-OAEP wrap → RSA-PSS sign</b>. Plaintext is never stored.</p>
  <div class="grid3">
    <div class="card"><h2>📥 Inbox</h2><p class="muted">Reports sealed for you.</p><h1>{{inbox()}}</h1><a routerLink="/inbox">Open inbox →</a></div>
    <div class="card"><h2>📤 Sent</h2><p class="muted">Reports you sealed.</p><h1>{{sentCount()}}</h1><a routerLink="/compose">Send new report →</a></div>
    <div class="card"><h2>🛡️ Audit chain</h2><p class="muted">Tamper-evident log.</p><h1>{{chainOk()===null?'…':(chainOk()?'✔ INTACT':'✖ BROKEN')}}</h1><a routerLink="/audit">Inspect log →</a></div>
  </div>
  <div class="card">
    <h2>Security posture (live from backend)</h2>
    <div class="kv" *ngIf="overview">
      <b>Bulk cipher</b><span class="mono">{{overview.policy.bulk_cipher}}</span>
      <b>Key wrap</b><span class="mono">{{overview.policy.key_wrap}}</span>
      <b>Signature</b><span class="mono">{{overview.policy.signature}}</span>
      <b>Hash</b><span class="mono">{{overview.policy.hash}}</span>
      <b>Replay guard</b><span class="mono">{{overview.policy.replay_protection}}</span>
    </div>
  </div>
  <div class="card steps">
    <h2>3-click evaluator path</h2>
    <ol>
      <li><a routerLink="/compose">Send a report</a> as <b class="mono">dr_asha</b> → <b class="mono">dr_rohan</b>.</li>
      <li>Log in as <b class="mono">dr_rohan</b>, open it in <a routerLink="/inbox">Inbox</a> — watch GCM + SHA-256 + RSA-PSS all verify.</li>
      <li>Open <a routerLink="/attacker-lab">Attacker Lab</a> — flip a bit, forge a signature, replay the envelope — watch each attack get caught.</li>
    </ol>
  </div>`,
})
export class DashboardComponent implements OnInit {
  auth = inject(AuthService);
  private api = inject(ApiService);
  inbox = signal(0); sentCount = signal(0);
  chainOk = signal<boolean | null>(null);
  overview: any = null;
  ngOnInit() {
    this.api.inbox().subscribe({ next: (r: any[]) => this.inbox.set(r.length) });
    this.api.sent().subscribe({ next: (r: any[]) => this.sentCount.set(r.length) });
    this.api.auditVerify().subscribe({ next: (v: any) => this.chainOk.set(v.ok) });
    this.api.securityOverview().subscribe({ next: (o) => (this.overview = o) });
  }
}
