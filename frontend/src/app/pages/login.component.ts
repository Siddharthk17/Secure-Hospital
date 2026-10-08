import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { ApiService } from '../services/api.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
  <span class="eyebrow">SECURE HOSPITAL EXCHANGE · CNS FA</span>
  <h1 class="hero-title">Patient reports. <em>Sealed. Verified.</em></h1>
  <p class="hero-sub">Every report leaves the sender as AES-256-GCM ciphertext, wrapped for one recipient, signed by its author — and it is verified three ways before anyone reads a word.</p>
  <ul class="feat-list">
    <li><svg class="chev" viewBox="0 0 11 20"><path d="M1.15 1.15 L9.6 10 L1.15 18.85"/></svg>Only the recipient reads</li>
    <li><svg class="chev" viewBox="0 0 11 20"><path d="M1.15 1.15 L9.6 10 L1.15 18.85"/></svg>Any edit is detected</li>
    <li><svg class="chev" viewBox="0 0 11 20"><path d="M1.15 1.15 L9.6 10 L1.15 18.85"/></svg>Authorship is provable</li>
    <li><svg class="chev" viewBox="0 0 11 20"><path d="M1.15 1.15 L9.6 10 L1.15 18.85"/></svg>Every action audited</li>
  </ul>
  <div class="grid2" style="margin-top:18px">
    <div class="card">
      <h2>Secure sign-in</h2>
      <p class="muted">PBKDF2-verified passwords · throttled login · 15-min JWT + rotating refresh.</p>
      <label>Username<input [(ngModel)]="username" placeholder="dr_asha" /></label>
      <label>Password<input [(ngModel)]="password" type="password" placeholder="••••••••" /></label>
      <button class="primary" (click)="doLogin()" [disabled]="busy">{{busy?'Verifying…':'Login'}}</button>
      <div *ngIf="error" class="alert bad">{{error}}</div>
      <h3>Demo accounts (seeded)</h3>
      <table><tr><th>User</th><th>Password</th><th>Role</th></tr>
      <tr *ngFor="let d of demo"><td class="mono">{{d[0]}}</td><td class="mono">{{d[1]}}</td><td>{{d[2]}}</td></tr></table>
    </div>
    <div class="card steps">
      <h2>What happens at login?</h2>
      <ol>
        <li><b>Authentication</b> — password checked with PBKDF2-HMAC-SHA256 (600k iterations).</li>
        <li><b>JWT issued</b> — 15-min access token; every API call carries it.</li>
        <li><b>Keys resolved</b> — your dual RSA keypairs (encryption + signing) + CA certificate load.</li>
        <li><b>Audit</b> — sign-in is hash-chained into the tamper-evident log.</li>
      </ol>
      <div class="alert ok">Evaluators: log in as <b class="mono">dr_asha / Cardio&#64;123</b>, send a report to <b class="mono">dr_rohan</b>, then log in as <b class="mono">dr_rohan / Radio&#64;123</b> to decrypt + verify.</div>
    </div>
  </div>
  <span class="rule" aria-hidden="true" style="display:block"></span>`,
})
export class LoginComponent {
  private auth = inject(AuthService);
  private api = inject(ApiService);
  private router = inject(Router);
  username = 'dr_asha'; password = 'Cardio@123';
  busy = false; error = '';
  demo = [['admin','Admin@123','admin'],['dr_asha','Cardio@123','doctor · Cardiology'],
          ['dr_rohan','Radio@123','doctor · Radiology'],['lab_meera','Lab@1234','lab'],
          ['pharma_kabir','Pharma@123','pharmacist']];

  doLogin() {
    this.busy = true; this.error = '';
    this.auth.login(this.username, this.password).subscribe({
      next: (t: any) => {
        // Save tokens FIRST — the profile fetch itself is authenticated.
        this.auth.saveSession(t, { username: this.username });
        this.api.me().subscribe({
          next: (p) => { this.auth.saveSession(t, { username: this.username, ...p }); this.router.navigate(['/']); },
          error: () => { this.error = 'Login ok but profile load failed.'; this.busy = false; },
        });
      },
      error: (e) => { this.error = e?.error?.detail || 'Invalid credentials (or account locked by throttling).'; this.busy = false; },
    });
  }
}
