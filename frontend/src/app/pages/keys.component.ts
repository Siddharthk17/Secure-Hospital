import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../services/api.service';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-keys',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
  <span class="eyebrow">PKI · DUAL KEYPAIRS · ROTATION</span>
  <h1 class="hero-title">Keys, <em>owned for life.</em></h1>
  <p class="muted">Dual RSA keypairs per user (encryption vs signing) · SHA-256 fingerprints · Hospital-CA certificates · rotation + revocation.</p>
  <div class="card"><h2>Your identity — {{auth.username()}}</h2>
    <div class="kv" *ngIf="mine"><b>Role / Dept</b><span>{{mine.role}} / {{mine.department}}</span>
    <b>Key fingerprint</b><span class="mono">{{mine.key_fingerprint}}</span><b>Version</b><span>v{{mine.key_version}}</span>
    <b>CA cert</b><span class="mono">{{mine.ca_certificate?.slice(0,60)}}…</span></div>
    <button class="good" (click)="rotate()">🔄 Rotate my keys</button>
    <span class="muted"> Old ciphertext stays openable — versions are tracked per report.</span>
  </div>
  <div class="card"><h2>Staff directory + new staff</h2>
    <table><tr><th>User</th><th>Role</th><th>Dept</th><th>Fingerprint</th><th>v</th></tr>
    <tr *ngFor="let u of staff()"><td class="mono">{{u.username}}</td><td>{{u.role}}</td><td>{{u.department}}</td><td class="mono">{{u.key_fingerprint}}</td><td>{{u.key_version}}</td></tr></table>
    <h3>Register staff (issues fresh keypairs + CA cert)</h3>
    <div class="grid3">
      <input [(ngModel)]="n.username" placeholder="username" />
      <input [(ngModel)]="n.password" placeholder="password (8+ chars)" type="password" />
      <input [(ngModel)]="n.department" placeholder="department" />
    </div>
    <div class="grid3">
      <select [(ngModel)]="n.role"><option>doctor</option><option>lab</option><option>pharmacist</option><option>admin</option></select>
      <button class="primary" (click)="create()">Create + issue keys</button>
    </div>
    <div *ngIf="msg" class="alert ok">{{msg}}</div><div *ngIf="err" class="alert bad">{{err}}</div>
  </div>`,
})
export class KeysComponent implements OnInit {
  auth = inject(AuthService);
  private api = inject(ApiService);
  staff = signal<any[]>([]); mine: any = null;
  n: any = { username: '', password: '', role: 'doctor', department: 'Cardiology' };
  msg = ''; err = '';
  ngOnInit() { this.refresh(); }
  refresh() {
    this.api.users().subscribe({ next: (u) => { this.staff.set(u); this.mine = u.find((x: any) => x.username === this.auth.username()); } });
  }
  rotate() { this.api.rotateKeys().subscribe({ next: () => { this.msg = 'Keys rotated.'; this.refresh(); } }); }
  create() {
    this.msg = ''; this.err = '';
    this.api.register(this.n).subscribe({ next: (r) => { this.msg = `Created ${r.username} · ${r.key_fingerprint}`; this.refresh(); }, error: (e) => (this.err = JSON.stringify(e?.error || e)) });
  }
}
